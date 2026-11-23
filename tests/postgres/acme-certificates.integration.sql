-- Integration test for Migration 022: ACME Certificate Lifecycle
BEGIN;

-- Setup test user, tenant and domain claim
CREATE TEMP TABLE test_ctx AS
SELECT
  '10000000-0000-4000-8000-000000000001'::uuid AS tenant_id,
  '20000000-0000-4000-8000-000000000001'::uuid AS owner_id;

-- Insert domain claim for certificate testing
INSERT INTO public.domain_claims (
  id, tenant_id, hostname, status, created_by, verified_at
)
SELECT
  '55000000-0000-4000-8000-000000000001'::uuid,
  tenant_id,
  'app.example.com',
  'verified',
  owner_id,
  now()
FROM test_ctx;

-- Insert active TLS certificate
INSERT INTO public.domain_tls_certificates (
  tenant_id,
  domain_claim_id,
  status,
  issuer,
  serial_number,
  sha256_fingerprint,
  not_before,
  not_after,
  auto_renew
)
SELECT
  tenant_id,
  '55000000-0000-4000-8000-000000000001'::uuid,
  'active',
  'letsencrypt',
  '1234567890abcdef',
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  now() - interval '10 days',
  now() + interval '80 days',
  true
FROM test_ctx;

-- Verify certificate insertion
DO $$
DECLARE
  v_count integer;
BEGIN
  SELECT count(*) INTO v_count
    FROM public.domain_tls_certificates
   WHERE domain_claim_id = '55000000-0000-4000-8000-000000000001'::uuid
     AND status = 'active';
  IF v_count <> 1 THEN
    RAISE EXCEPTION 'Expected 1 active TLS certificate, found %', v_count;
  END IF;
END $$;

-- Verify duplicate active certificate constraint fails
DO $$
DECLARE
  ctx record;
BEGIN
  SELECT * INTO ctx FROM test_ctx;
  BEGIN
    INSERT INTO public.domain_tls_certificates (
      tenant_id, domain_claim_id, status, issuer
    ) VALUES (
      ctx.tenant_id, '55000000-0000-4000-8000-000000000001'::uuid, 'issuing', 'letsencrypt'
    );
    RAISE EXCEPTION 'Second active/issuing certificate should have failed unique constraint';
  EXCEPTION WHEN unique_violation THEN
    -- Expected unique violation
    NULL;
  END;
END $$;

-- Verify validity window check constraint (not_after must be after not_before)
DO $$
DECLARE
  ctx record;
BEGIN
  SELECT * INTO ctx FROM test_ctx;
  BEGIN
    INSERT INTO public.domain_tls_certificates (
      tenant_id, domain_claim_id, status, issuer, not_before, not_after
    ) VALUES (
      ctx.tenant_id, '55000000-0000-4000-8000-000000000002'::uuid, 'expired', 'letsencrypt', now(), now() - interval '1 day'
    );
    RAISE EXCEPTION 'Inverted validity window should have failed check constraint';
  EXCEPTION WHEN check_violation THEN
    -- Expected check constraint violation
    NULL;
  END;
END $$;

ROLLBACK;
