-- Integration test for Migration 021: Persistent Application Volumes
BEGIN;

-- Setup test user and tenant
CREATE TEMP TABLE test_ctx AS
SELECT
  '10000000-0000-4000-8000-000000000001'::uuid AS tenant_id,
  '20000000-0000-4000-8000-000000000001'::uuid AS owner_id,
  '30000000-0000-4000-8000-000000000001'::uuid AS app_id;

-- Insert application volume
INSERT INTO public.application_volumes (
  tenant_id,
  application_id,
  name,
  mount_path,
  size_bytes,
  status,
  read_only,
  driver
)
SELECT
  tenant_id,
  app_id,
  'postgres-data',
  '/var/lib/postgresql/data',
  10737418240, -- 10 GB
  'detached',
  false,
  'local_dir'
FROM test_ctx;

-- Verify volume insertion
DO $$
DECLARE
  v_count integer;
BEGIN
  SELECT count(*) INTO v_count
    FROM public.application_volumes
   WHERE name = 'postgres-data'
     AND mount_path = '/var/lib/postgresql/data';
  IF v_count <> 1 THEN
    RAISE EXCEPTION 'Expected 1 application volume, found %', v_count;
  END IF;
END $$;

-- Verify duplicate name constraint fails
DO $$
DECLARE
  ctx record;
BEGIN
  SELECT * INTO ctx FROM test_ctx;
  BEGIN
    INSERT INTO public.application_volumes (
      tenant_id, application_id, name, mount_path, size_bytes
    ) VALUES (
      ctx.tenant_id, ctx.app_id, 'postgres-data', '/other/path', 104857600
    );
    RAISE EXCEPTION 'Duplicate volume name should have failed unique constraint';
  EXCEPTION WHEN unique_violation THEN
    -- Expected
    NULL;
  END;
END $$;

-- Verify duplicate mount path constraint fails
DO $$
DECLARE
  ctx record;
BEGIN
  SELECT * INTO ctx FROM test_ctx;
  BEGIN
    INSERT INTO public.application_volumes (
      tenant_id, application_id, name, mount_path, size_bytes
    ) VALUES (
      ctx.tenant_id, ctx.app_id, 'second-vol', '/var/lib/postgresql/data', 104857600
    );
    RAISE EXCEPTION 'Duplicate mount path should have failed unique constraint';
  EXCEPTION WHEN unique_violation THEN
    -- Expected
    NULL;
  END;
END $$;

-- Create backup record
INSERT INTO public.volume_backups (
  tenant_id,
  volume_id,
  status,
  size_bytes,
  sha256_checksum,
  backup_location,
  retention_days
)
SELECT
  v.tenant_id,
  v.id,
  'completed',
  1024 * 1024 * 50,
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  's3://cloudexify-backups/postgres-data-2026-11-23.tar.gz',
  30
FROM public.application_volumes v
WHERE v.name = 'postgres-data';

-- Verify backup insertion
DO $$
DECLARE
  b_count integer;
BEGIN
  SELECT count(*) INTO b_count
    FROM public.volume_backups
   WHERE status = 'completed';
  IF b_count <> 1 THEN
    RAISE EXCEPTION 'Expected 1 volume backup, found %', b_count;
  END IF;
END $$;

ROLLBACK;
