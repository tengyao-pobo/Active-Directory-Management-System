-- Unconsumed owner-only predicate. Live catalog attestation must pin this function before calling it.
-- Manifest hashes independent source roots; no source root embeds this generated constant.
CREATE FUNCTION enrollment_execution.profile4_ready() RETURNS boolean
LANGUAGE plpgsql STABLE PARALLEL UNSAFE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET row_security=on AS $function$
DECLARE
    expected_manifest constant bytea := decode('2f5386a0255f2b859393ceccc8edc8e36097d6a86ba401f4977eaf98d3e82579','hex');
    valid boolean;
BEGIN
    IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class relation
        WHERE relation.oid=pg_catalog.to_regclass('enrollment_execution.profile4_readiness')
          AND relation.relowner=CURRENT_USER::regrole::oid AND relation.relkind='r' AND relation.relpersistence='p'
          AND NOT relation.relispartition AND NOT relation.relrowsecurity AND NOT relation.relforcerowsecurity)
       OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class relation
        WHERE relation.oid=pg_catalog.to_regclass('public."Environments"') AND relation.relowner=CURRENT_USER::regrole::oid)
       OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles role WHERE role.rolname=CURRENT_USER AND role.rolcanlogin
        AND NOT(role.rolsuper OR role.rolbypassrls OR role.rolcreatedb OR role.rolcreaterole OR role.rolinherit OR role.rolreplication)
        AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members membership WHERE membership.member=role.oid OR membership.roleid=role.oid)) THEN
        RETURN false;
    END IF;
    SELECT count(*)=1 AND bool_and((singleton AND profile_version=4 AND generation>0
        AND installation_nonce<>'00000000-0000-0000-0000-000000000000'::uuid
        AND attestation_manifest_sha256=expected_manifest AND state='Ready'
        AND pending_at IS NOT NULL AND isfinite(pending_at)
        AND ready_at IS NOT NULL AND isfinite(ready_at) AND ready_at>=pending_at
        AND ready_by=CURRENT_USER::name) IS TRUE)
      INTO valid FROM enrollment_execution.profile4_readiness;
    RETURN valid IS TRUE;
END
$function$;
REVOKE ALL ON FUNCTION enrollment_execution.profile4_ready() FROM PUBLIC;
