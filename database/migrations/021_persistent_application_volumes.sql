BEGIN;

-- Persistent application volumes foundation.
-- RLS uses the tenant-membership helpers established by migration 001.
-- Do not reference current_tenant_id/current_user_role: neither exists in this schema.

CREATE TABLE IF NOT EXISTS public.application_volumes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
  application_id uuid NOT NULL REFERENCES public.applications(id) ON DELETE CASCADE,
  name text NOT NULL,
  mount_path text NOT NULL,
  size_bytes bigint NOT NULL CHECK (size_bytes >= 10485760 AND size_bytes <= 1099511627776),
  status text NOT NULL DEFAULT 'detached' CHECK (status IN ('detached', 'attaching', 'attached', 'detaching', 'error')),
  attached_node_id uuid REFERENCES public.nodes(id) ON DELETE SET NULL,
  attached_deployment_id uuid REFERENCES public.deployments(id) ON DELETE SET NULL,
  read_only boolean NOT NULL DEFAULT false,
  driver text NOT NULL DEFAULT 'local_dir' CHECK (driver IN ('local_dir', 'nfs', 'btrfs_subvol', 'zfs_dataset')),
  storage_path text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT application_volumes_name_valid CHECK (name ~ '^[a-z0-9]([a-z0-9_-]{0,61}[a-z0-9])?$'),
  CONSTRAINT application_volumes_mount_path_valid CHECK (mount_path ~ '^/[a-zA-Z0-9_.-]+(/[a-zA-Z0-9_.-]+)*$'),
  CONSTRAINT application_volumes_unique_name UNIQUE (tenant_id, application_id, name),
  CONSTRAINT application_volumes_unique_mount UNIQUE (tenant_id, application_id, mount_path)
);

COMMENT ON TABLE public.application_volumes IS
  'Persistent storage volumes bound to applications with lifecycle and node attachment states.';

CREATE TABLE IF NOT EXISTS public.volume_backups (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
  volume_id uuid NOT NULL REFERENCES public.application_volumes(id) ON DELETE CASCADE,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'in_progress', 'completed', 'failed', 'restoring')),
  size_bytes bigint CHECK (size_bytes IS NULL OR size_bytes >= 0),
  sha256_checksum text CHECK (sha256_checksum IS NULL OR sha256_checksum ~ '^[a-f0-9]{64}$'),
  backup_location text,
  retention_days integer NOT NULL DEFAULT 30 CHECK (retention_days BETWEEN 1 AND 365),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  completed_at timestamptz
);

COMMENT ON TABLE public.volume_backups IS
  'Backup snapshots and retention records for persistent application volumes.';

CREATE INDEX IF NOT EXISTS application_volumes_tenant_app_idx
  ON public.application_volumes (tenant_id, application_id);

CREATE INDEX IF NOT EXISTS application_volumes_attached_node_idx
  ON public.application_volumes (attached_node_id)
  WHERE attached_node_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS application_volumes_status_idx
  ON public.application_volumes (status);

CREATE INDEX IF NOT EXISTS volume_backups_tenant_volume_idx
  ON public.volume_backups (tenant_id, volume_id);

CREATE INDEX IF NOT EXISTS volume_backups_status_idx
  ON public.volume_backups (status);

-- Helper for the one operation that intentionally permits Operators.
-- SECURITY DEFINER mirrors the established tenant-membership helper pattern.
CREATE OR REPLACE FUNCTION app_private.has_tenant_role(
  target_tenant_id uuid,
  allowed_roles text[]
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
  SELECT EXISTS (
    SELECT 1
    FROM public.tenant_memberships AS membership
    WHERE membership.tenant_id = target_tenant_id
      AND membership.user_id = app_private.current_user_id()
      AND membership.status = 'active'
      AND membership.role = ANY (allowed_roles)
  )
$function$;

GRANT EXECUTE ON FUNCTION app_private.has_tenant_role(uuid, text[]) TO PUBLIC;

ALTER TABLE public.application_volumes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.volume_backups ENABLE ROW LEVEL SECURITY;

-- Make policy creation safe if this migration is retried after manual recovery.
DROP POLICY IF EXISTS application_volumes_tenant_read ON public.application_volumes;
DROP POLICY IF EXISTS application_volumes_owner_admin_insert ON public.application_volumes;
DROP POLICY IF EXISTS application_volumes_owner_admin_update ON public.application_volumes;
DROP POLICY IF EXISTS application_volumes_owner_admin_delete ON public.application_volumes;
DROP POLICY IF EXISTS volume_backups_tenant_read ON public.volume_backups;
DROP POLICY IF EXISTS volume_backups_owner_admin_insert ON public.volume_backups;
DROP POLICY IF EXISTS volume_backups_owner_admin_update ON public.volume_backups;

CREATE POLICY application_volumes_tenant_read
  ON public.application_volumes
  FOR SELECT
  TO cloudexify_runtime
  USING (app_private.is_tenant_member(tenant_id));

CREATE POLICY application_volumes_owner_admin_insert
  ON public.application_volumes
  FOR INSERT
  TO cloudexify_runtime
  WITH CHECK (app_private.can_manage_tenant(tenant_id));

CREATE POLICY application_volumes_owner_admin_update
  ON public.application_volumes
  FOR UPDATE
  TO cloudexify_runtime
  USING (app_private.can_manage_tenant(tenant_id))
  WITH CHECK (app_private.can_manage_tenant(tenant_id));

CREATE POLICY application_volumes_owner_admin_delete
  ON public.application_volumes
  FOR DELETE
  TO cloudexify_runtime
  USING (app_private.can_manage_tenant(tenant_id));

CREATE POLICY volume_backups_tenant_read
  ON public.volume_backups
  FOR SELECT
  TO cloudexify_runtime
  USING (app_private.is_tenant_member(tenant_id));

CREATE POLICY volume_backups_owner_admin_insert
  ON public.volume_backups
  FOR INSERT
  TO cloudexify_runtime
  WITH CHECK (
    app_private.has_tenant_role(tenant_id, ARRAY['owner', 'admin', 'operator'])
  );

CREATE POLICY volume_backups_owner_admin_update
  ON public.volume_backups
  FOR UPDATE
  TO cloudexify_runtime
  USING (app_private.can_manage_tenant(tenant_id))
  WITH CHECK (app_private.can_manage_tenant(tenant_id));

COMMIT;
