BEGIN;

-- Persistent application volumes foundation (Milestone 3 / Section 7)
-- Provides durable volume reservations, attachment state tracking,
-- and backup lifecycle records with strict tenant isolation.

CREATE TABLE public.application_volumes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
  application_id uuid NOT NULL REFERENCES public.applications(id) ON DELETE CASCADE,
  name text NOT NULL,
  mount_path text NOT NULL,
  size_bytes bigint NOT NULL CHECK (size_bytes >= 10485760 AND size_bytes <= 1099511627776), -- 10MB to 1TB
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

CREATE TABLE public.volume_backups (
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

-- Indexes
CREATE INDEX application_volumes_tenant_app_idx
  ON public.application_volumes (tenant_id, application_id);

CREATE INDEX application_volumes_attached_node_idx
  ON public.application_volumes (attached_node_id)
  WHERE attached_node_id IS NOT NULL;

CREATE INDEX application_volumes_status_idx
  ON public.application_volumes (status);

CREATE INDEX volume_backups_tenant_volume_idx
  ON public.volume_backups (tenant_id, volume_id);

CREATE INDEX volume_backups_status_idx
  ON public.volume_backups (status);

-- Enable Row-Level Security
ALTER TABLE public.application_volumes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.volume_backups ENABLE ROW LEVEL SECURITY;

-- Volume RLS: Viewers/Operators/Admins/Owners can read within tenant
CREATE POLICY application_volumes_tenant_read
  ON public.application_volumes
  FOR SELECT
  TO cloudexify_runtime
  USING (tenant_id = app_private.current_tenant_id());

-- Volume RLS: Owners and Admins can create volumes
CREATE POLICY application_volumes_owner_admin_insert
  ON public.application_volumes
  FOR INSERT
  TO cloudexify_runtime
  WITH CHECK (
    tenant_id = app_private.current_tenant_id()
    AND app_private.current_user_role(app_private.current_tenant_id()) IN ('owner', 'admin')
  );

-- Volume RLS: Owners and Admins can update volumes
CREATE POLICY application_volumes_owner_admin_update
  ON public.application_volumes
  FOR UPDATE
  TO cloudexify_runtime
  USING (
    tenant_id = app_private.current_tenant_id()
    AND app_private.current_user_role(app_private.current_tenant_id()) IN ('owner', 'admin')
  )
  WITH CHECK (
    tenant_id = app_private.current_tenant_id()
    AND app_private.current_user_role(app_private.current_tenant_id()) IN ('owner', 'admin')
  );

-- Volume RLS: Owners and Admins can delete volumes
CREATE POLICY application_volumes_owner_admin_delete
  ON public.application_volumes
  FOR DELETE
  TO cloudexify_runtime
  USING (
    tenant_id = app_private.current_tenant_id()
    AND app_private.current_user_role(app_private.current_tenant_id()) IN ('owner', 'admin')
  );

-- Backup RLS: Read within tenant
CREATE POLICY volume_backups_tenant_read
  ON public.volume_backups
  FOR SELECT
  TO cloudexify_runtime
  USING (tenant_id = app_private.current_tenant_id());

-- Backup RLS: Owners and Admins can manage backups
CREATE POLICY volume_backups_owner_admin_insert
  ON public.volume_backups
  FOR INSERT
  TO cloudexify_runtime
  WITH CHECK (
    tenant_id = app_private.current_tenant_id()
    AND app_private.current_user_role(app_private.current_tenant_id()) IN ('owner', 'admin', 'operator')
  );

CREATE POLICY volume_backups_owner_admin_update
  ON public.volume_backups
  FOR UPDATE
  TO cloudexify_runtime
  USING (
    tenant_id = app_private.current_tenant_id()
    AND app_private.current_user_role(app_private.current_tenant_id()) IN ('owner', 'admin')
  )
  WITH CHECK (
    tenant_id = app_private.current_tenant_id()
    AND app_private.current_user_role(app_private.current_tenant_id()) IN ('owner', 'admin')
  );

COMMIT;
