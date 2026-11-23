BEGIN;

-- 022_acme_certificate_lifecycle.sql
-- Managed TLS certificates, ACME automation metadata, and SNI certificate tracking.
-- Supports automated renewal, validity checks, and tenant isolation via RLS.

CREATE TABLE public.domain_tls_certificates (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE RESTRICT,
  domain_claim_id uuid NOT NULL,
  status text NOT NULL DEFAULT 'issuing'
    CHECK (status IN ('issuing', 'active', 'renewing', 'expired', 'revoked')),
  issuer text NOT NULL DEFAULT 'letsencrypt'
    CHECK (issuer IN ('letsencrypt', 'zerossl', 'custom_ca', 'self_signed')),
  serial_number text,
  sha256_fingerprint text CHECK (sha256_fingerprint IS NULL OR sha256_fingerprint ~ '^[0-9a-f]{64}$'),
  not_before timestamptz,
  not_after timestamptz,
  auto_renew boolean NOT NULL DEFAULT true,
  renewal_attempts integer NOT NULL DEFAULT 0 CHECK (renewal_attempts >= 0),
  last_renewed_at timestamptz,
  certificate_pem text,
  chain_pem text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT domain_tls_certificates_validity_window CHECK (
    (not_before IS NULL AND not_after IS NULL) OR
    (not_before IS NOT NULL AND not_after IS NOT NULL AND not_after > not_before)
  ),
  FOREIGN KEY (domain_claim_id, tenant_id)
    REFERENCES public.domain_claims(id, tenant_id) ON DELETE RESTRICT
);

-- At most one active/issuing/renewing certificate per domain claim
CREATE UNIQUE INDEX domain_tls_certificates_one_active_per_domain
  ON public.domain_tls_certificates (domain_claim_id)
  WHERE status IN ('active', 'issuing', 'renewing');

CREATE INDEX domain_tls_certificates_tenant_idx
  ON public.domain_tls_certificates (tenant_id, created_at DESC);

CREATE INDEX domain_tls_certificates_expiry_idx
  ON public.domain_tls_certificates (not_after)
  WHERE status = 'active' AND auto_renew = true;

CREATE TRIGGER domain_tls_certificates_set_updated_at
  BEFORE UPDATE ON public.domain_tls_certificates
  FOR EACH ROW EXECUTE FUNCTION app_private.set_updated_at();

ALTER TABLE public.domain_tls_certificates ENABLE ROW LEVEL SECURITY;

CREATE POLICY domain_tls_certificates_read_member
  ON public.domain_tls_certificates FOR SELECT
  USING (app_private.is_tenant_member(tenant_id));

COMMIT;
