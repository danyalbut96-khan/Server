import { constants } from "node:fs";
import { chmod, lstat, mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";

export function defaultStateDirectory(env = process.env) {
  return env.CLOUDEXIFY_AGENT_STATE_DIR || path.join(os.homedir(), ".local", "share", "cloudexify-agent");
}

async function secureDirectory(directory) {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const info = await lstat(directory);
  if (info.isSymbolicLink() || !info.isDirectory()) throw new Error("Agent state path must be a real directory, not a symlink.");
  if (typeof process.getuid === "function" && info.uid !== process.getuid()) throw new Error("Agent state directory must be owned by the current user.");
  await chmod(directory, 0o700);
}

function validateState(state) {
  if (!state || typeof state !== "object" || Array.isArray(state) ||
      typeof state.node_id !== "string" || !/^[0-9a-f-]{36}$/i.test(state.node_id) ||
      typeof state.credential !== "string" || !/^[A-Za-z0-9_-]{40,128}$/.test(state.credential) ||
      typeof state.control_plane_url !== "string" || typeof state.node_name !== "string") {
    throw new Error("Agent state file is invalid; re-enroll this node.");
  }
  return state;
}

export async function saveAgentState(directory, state) {
  await secureDirectory(directory);
  const target = path.join(directory, "node.json");
  const temporary = path.join(directory, ".node-" + randomBytes(8).toString("hex") + ".tmp");
  let handle;
  try {
    handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW || 0), 0o600);
    await handle.writeFile(JSON.stringify(validateState(state)) + "\n", { encoding: "utf8" });
    await handle.sync();
    await handle.close();
    handle = null;
    await rename(temporary, target);
    await chmod(target, 0o600);
    if (process.platform !== "win32") {
      const dirHandle = await open(directory, constants.O_RDONLY);
      try { await dirHandle.sync(); } finally { await dirHandle.close(); }
    }
  } catch (error) {
    if (handle) await handle.close().catch(() => {});
    await unlink(temporary).catch(() => {});
    throw error;
  }
}

export async function loadAgentState(directory) {
  await secureDirectory(directory);
  const target = path.join(directory, "node.json");
  const info = await lstat(target);
  if (info.isSymbolicLink() || !info.isFile()) throw new Error("Agent credential file must be a regular file, not a symlink.");
  if (typeof process.getuid === "function" && info.uid !== process.getuid()) throw new Error("Agent credential file must be owned by the current user.");
  if (process.platform !== "win32" && (info.mode & 0o077) !== 0) throw new Error("Agent credential file permissions are too open; expected 0600.");
  if (info.size > 4096) throw new Error("Agent credential file exceeds the allowed size.");
  const handle = await open(target, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
  try {
    const content = await handle.readFile({ encoding: "utf8" });
    return validateState(JSON.parse(content));
  } finally { await handle.close(); }
}
