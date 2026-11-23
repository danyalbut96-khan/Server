import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { normalizeIngressHostname, createIngressRequestHandler } from "../src/ingress/http-proxy.mjs";

const route = {
  route_id: "31000000-0000-4000-8000-000000000001",
  route_version: 2,
  tenant_id: "20000000-0000-4000-8000-000000000001",
  hostname: "app.example.test",
  deployment_id: "50000000-0000-4000-8000-000000000001",
  node_id: "30000000-0000-4000-8000-000000000001",
  local_port: 32145
};

test("hostname normalization rejects malformed, IP and authority injection", () => {
  assert.equal(normalizeIngressHostname("App.Example.Test:443"), "app.example.test");
  assert.equal(normalizeIngressHostname("app.example.test."), "app.example.test");
  assert.equal(normalizeIngressHostname("127.0.0.1"), null);
  assert.equal(normalizeIngressHostname("localhost"), null);
  assert.equal(normalizeIngressHostname("app.example.test,evil.test"), null);
  assert.equal(normalizeIngressHostname("user@app.example.test"), null);
  assert.equal(normalizeIngressHostname("https://app.example.test/path"), null);
});

test("HTTPS ingress handler proxies HTTP over an authenticated route stream", async (t) => {
  let receivedRequest = "";
  let responseSent = false;
  const pool = {
    async query(sql, params) {
      if (sql.includes("WHERE route.id = $1")) {
        assert.equal(sql.includes("node.ingress_draining = false"), false, "in-flight revalidation must remain valid while node drains");
        assert.deepEqual(params, [route.route_id, route.route_version, route.node_id, "app.example.test", route.deployment_id, route.local_port]);
        return { rows: [route] };
      }
      assert.equal(sql.includes("node.ingress_draining = false"), true, "new route lookups must exclude draining nodes");
      assert.deepEqual(params, ["app.example.test"]);
      return { rows: [route] };
    }
  };
  const routeStreams = {
    hasNode: (id) => id === route.node_id,
    async openStream({ nodeId, grant, onData }) {
      assert.equal(nodeId, route.node_id);
      assert.equal(grant, "signed-route-grant");
      return {
        write(chunk) {
          receivedRequest += chunk.toString();
          const headerEnd = receivedRequest.indexOf("\r\n\r\n");
          const length = Number(receivedRequest.match(/content-length: (\d+)/i)?.[1] || 0);
          const bodyBytes = headerEnd < 0 ? 0 : Buffer.byteLength(receivedRequest.slice(headerEnd + 4));
          if (!responseSent && headerEnd >= 0 && bodyBytes >= length) {
            responseSent = true;
            queueMicrotask(() => onData({
              streamId: "test-stream",
              nodeId,
              data: Buffer.from("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\nX-Upstream: test\r\n\r\nhello")
            }));
          }
          return true;
        },
        onDrain: () => true,
        pause: () => true,
        resume: () => true,
        close: () => {}
      };
    }
  };
  const handler = createIngressRequestHandler({
    pool,
    routeStreams,
    signRouteGrant: (value) => { assert.equal(value.route_id, route.route_id); return { token: "signed-route-grant" }; },
    certificate: { checkHost: () => true }
  });
  const server = http.createServer((req, res) => { void handler(req, res); });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const response = await new Promise((resolve, reject) => {
    const req = http.request({
      host: "127.0.0.1",
      port: server.address().port,
      path: "/hello?from=test",
      method: "POST",
      headers: { host: "app.example.test", "content-length": String(70 * 1024) }
    }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    req.once("error", reject);
    req.end("x".repeat(70 * 1024));
  });

  assert.equal(response.status, 200);
  assert.equal(response.body, "hello");
  assert.equal(response.headers["x-upstream"], "test");
  assert.match(receivedRequest, /^POST \/hello\?from=test HTTP\/1\.1\r\n/);
  assert.equal(Buffer.byteLength(receivedRequest.slice(receivedRequest.indexOf("\r\n\r\n") + 4)), 70 * 1024);
  assert.match(receivedRequest, /host: app\.example\.test/i);
  assert.match(receivedRequest, /x-forwarded-proto: https/i);
});

test("ingress returns 404, 421 and 503 without opening a tunnel", async (t) => {
  let lookupRows = [];
  let connected = true;
  let certificateMatches = false;
  let opened = 0;
  const handler = createIngressRequestHandler({
    pool: { async query() { return { rows: lookupRows }; } },
    routeStreams: { hasNode: () => connected, async openStream() { opened += 1; throw new Error("must not open"); } },
    signRouteGrant: () => ({ token: "unused" }),
    certificate: { checkHost: () => certificateMatches }
  });
  const server = http.createServer((req, res) => { void handler(req, res); });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const call = (host) => new Promise((resolve, reject) => {
    const req = http.get({ host: "127.0.0.1", port: server.address().port, headers: { host } }, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode));
    });
    req.once("error", reject);
  });
  assert.equal(await call("app.example.test"), 421);
  certificateMatches = true;
  assert.equal(await call("missing.example.test"), 404);
  lookupRows = [route];
  connected = false;
  assert.equal(await call("app.example.test"), 503);
  assert.equal(opened, 0);
});

test("active ingress route is terminated when periodic revalidation detects revocation", async (t) => {
  let intervalCallback;
  let intervalCleared = false;
  let responseStatus;
  let revalidationCount = 0;
  const pool = {
    async query(sql) {
      if (sql.includes("WHERE route.id = $1")) {
        revalidationCount += 1;
        return { rows: [] };
      }
      return { rows: [route] };
    }
  };
  const routeStreams = {
    hasNode: () => true,
    async openStream() {
      return {
        write: () => true,
        onDrain: () => true,
        pause: () => true,
        resume: () => true,
        close: () => {}
      };
    }
  };
  const handler = createIngressRequestHandler({
    pool,
    routeStreams,
    signRouteGrant: () => ({ token: "signed-route-grant" }),
    certificate: { checkHost: () => true },
    revalidateIntervalMs: 1000,
    setIntervalImpl(callback, delay) {
      assert.equal(delay, 1000);
      intervalCallback = callback;
      return { unref() {} };
    },
    clearIntervalImpl() { intervalCleared = true; }
  });
  const server = http.createServer((req, res) => {
    res.once("finish", () => { responseStatus = res.statusCode; });
    void handler(req, res);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const responsePromise = new Promise((resolve, reject) => {
    const req = http.get({
      host: "127.0.0.1",
      port: server.address().port,
      headers: { host: "app.example.test" }
    }, (res) => {
      res.resume();
      res.once("end", () => resolve(res.statusCode));
    });
    req.once("error", reject);
  });

  for (let attempt = 0; attempt < 20 && !intervalCallback; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  assert.equal(typeof intervalCallback, "function");
  await intervalCallback();
  assert.equal(revalidationCount, 1);
  assert.equal(await responsePromise, 503);
  assert.equal(responseStatus, 503);
  assert.equal(intervalCleared, true);
});

test("active ingress route is terminated when periodic revalidation database access fails", async (t) => {
  let intervalCallback;
  let queryCount = 0;
  const pool = {
    async query(sql) {
      queryCount += 1;
      if (sql.includes("WHERE route.id = $1")) {
        throw new Error("database unavailable");
      }
      return { rows: [route] };
    }
  };
  const routeStreams = {
    hasNode: () => true,
    async openStream() {
      return {
        write: () => true,
        onDrain: () => true,
        pause: () => true,
        resume: () => true,
        close: () => {}
      };
    }
  };
  const handler = createIngressRequestHandler({
    pool,
    routeStreams,
    signRouteGrant: () => ({ token: "signed-route-grant" }),
    certificate: { checkHost: () => true },
    revalidateIntervalMs: 1000,
    setIntervalImpl(callback) {
      intervalCallback = callback;
      return { unref() {} };
    },
    clearIntervalImpl() {}
  });
  const server = http.createServer((req, res) => { void handler(req, res); });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const responsePromise = new Promise((resolve, reject) => {
    const req = http.get({
      host: "127.0.0.1",
      port: server.address().port,
      headers: { host: "app.example.test" }
    }, (res) => {
      res.resume();
      res.once("end", () => resolve(res.statusCode));
    });
    req.once("error", reject);
  });

  for (let attempt = 0; attempt < 20 && !intervalCallback; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  assert.equal(typeof intervalCallback, "function");
  await intervalCallback();
  assert.equal(queryCount, 2);
  assert.equal(await responsePromise, 503);
});

test("active ingress route is terminated when its authenticated node tunnel disappears", async (t) => {
  let intervalCallback;
  let connected = true;
  const pool = {
    async query() {
      return { rows: [route] };
    }
  };
  const routeStreams = {
    hasNode: () => connected,
    async openStream() {
      return {
        write: () => true,
        onDrain: () => true,
        pause: () => true,
        resume: () => true,
        close: () => {}
      };
    }
  };
  const handler = createIngressRequestHandler({
    pool,
    routeStreams,
    signRouteGrant: () => ({ token: "signed-route-grant" }),
    certificate: { checkHost: () => true },
    revalidateIntervalMs: 1000,
    setIntervalImpl(callback) {
      intervalCallback = callback;
      return { unref() {} };
    },
    clearIntervalImpl() {}
  });
  const server = http.createServer((req, res) => { void handler(req, res); });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const responsePromise = new Promise((resolve, reject) => {
    const req = http.get({
      host: "127.0.0.1",
      port: server.address().port,
      headers: { host: "app.example.test" }
    }, (res) => {
      res.resume();
      res.once("end", () => resolve(res.statusCode));
    });
    req.once("error", reject);
  });

  for (let attempt = 0; attempt < 20 && !intervalCallback; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  assert.equal(typeof intervalCallback, "function");
  connected = false;
  await intervalCallback();
  assert.equal(await responsePromise, 503);
});
