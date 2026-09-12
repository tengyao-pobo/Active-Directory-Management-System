-- Unconsumed foundation; no installer, runtime audit or readiness consumer includes this file.
-- The trusted owner can alter its objects. This guard is not proof of a history scan.
CREATE TABLE enrollment_execution.profile4_readiness (
 singleton boolean PRIMARY KEY CHECK (singleton),
 profile_version smallint NOT NULL CHECK (profile_version=4),
 generation bigint NOT NULL CHECK (generation>0),
 installation_nonce uuid NOT NULL CHECK (installation_nonce<>'00000000-0000-0000-0000-000000000000'::uuid),
 attestation_manifest_sha256 bytea NOT NULL CHECK (octet_length(attestation_manifest_sha256)=32),
 state text COLLATE "C" NOT NULL CHECK (state IN ('PendingHistoryAudit','Ready')),
 pending_at timestamptz NOT NULL CHECK (isfinite(pending_at)),
 ready_at timestamptz CHECK (isfinite(ready_at)),
 ready_by name,
 CONSTRAINT profile4_readiness_shape CHECK (
  (state='PendingHistoryAudit' AND ready_at IS NULL AND ready_by IS NULL)
  OR (state='Ready' AND ready_at IS NOT NULL AND ready_by IS NOT NULL AND ready_by<>'' AND ready_at>=pending_at))
);
REVOKE ALL ON TABLE enrollment_execution.profile4_readiness FROM PUBLIC;

CREATE FUNCTION enrollment_execution.guard_profile4_readiness() RETURNS trigger
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp SET row_security=on AS $function$
DECLARE expected_owner oid;
BEGIN
 SELECT relation.relowner INTO expected_owner FROM pg_catalog.pg_class relation
  WHERE relation.oid=TG_RELID AND relation.oid=pg_catalog.to_regclass('enrollment_execution.profile4_readiness')
    AND relation.relkind='r' AND relation.relpersistence='p' AND NOT relation.relispartition
    AND NOT relation.relrowsecurity AND NOT relation.relforcerowsecurity;
 IF TG_OP<>'UPDATE' OR expected_owner IS NULL OR CURRENT_USER<>SESSION_USER
  OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles role WHERE role.oid=expected_owner
    AND role.rolname=SESSION_USER AND role.rolcanlogin
    AND NOT(role.rolsuper OR role.rolbypassrls OR role.rolcreatedb OR role.rolcreaterole OR role.rolinherit OR role.rolreplication)) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Profile readiness transition context is invalid.';
 END IF;
 PERFORM pg_catalog.pg_advisory_xact_lock(1162235478,1);
 IF NEW.singleton IS DISTINCT FROM OLD.singleton OR NEW.profile_version IS DISTINCT FROM OLD.profile_version THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Profile readiness identity is immutable.';
 END IF;
 IF (OLD.state='PendingHistoryAudit' AND NEW.state='Ready'
     AND NEW.generation=OLD.generation AND NEW.installation_nonce=OLD.installation_nonce
     AND NEW.attestation_manifest_sha256=OLD.attestation_manifest_sha256 AND NEW.pending_at=OLD.pending_at
     AND NEW.ready_by=SESSION_USER AND NEW.ready_at>=OLD.pending_at AND isfinite(NEW.ready_at)) IS TRUE
  OR (OLD.state='Ready' AND NEW.state='PendingHistoryAudit'
     AND NEW.generation=OLD.generation+1 AND NEW.installation_nonce<>OLD.installation_nonce
     AND NEW.pending_at>=OLD.ready_at AND isfinite(NEW.pending_at)
     AND NEW.ready_at IS NULL AND NEW.ready_by IS NULL) IS TRUE THEN
  RETURN NEW;
 END IF;
 RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Profile readiness transition is invalid.';
END
$function$;
REVOKE ALL ON FUNCTION enrollment_execution.guard_profile4_readiness() FROM PUBLIC;
CREATE TRIGGER profile4_readiness_transition BEFORE UPDATE OR DELETE ON enrollment_execution.profile4_readiness
 FOR EACH ROW EXECUTE FUNCTION enrollment_execution.guard_profile4_readiness();
