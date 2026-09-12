-- Unconsumed candidate; CREATE OR REPLACE preserves the ordinary audit OID, owner and ACL.
CREATE OR REPLACE FUNCTION enrollment_execution.audit_execution_privileges(p_environment uuid)
RETURNS TABLE(is_valid boolean,diagnostic_code text,profile_version smallint)
LANGUAGE plpgsql STABLE PARALLEL UNSAFE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET row_security=on AS $function$
DECLARE
    expected_structure_hash constant text := 'b8c476078221bc98d3f82ccf523e84b110ad372bc15e8d63293b8e1195f6ce3f';
    owner_oid oid;
    row_count bigint;
    valid_count bigint;
    ready boolean;
BEGIN
    SELECT min(relation.relowner) INTO owner_oid FROM pg_catalog.pg_class relation
      WHERE relation.oid IN(pg_catalog.to_regclass('public."Environments"'),pg_catalog.to_regclass('enrollment_execution.role_reservations'))
      HAVING count(*)=2 AND count(DISTINCT relation.relowner)=1
        AND bool_and(relation.relowner=CURRENT_USER::regrole::oid AND relation.relkind='r' AND relation.relpersistence='p' AND NOT relation.relispartition);
    IF owner_oid IS NULL OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
        WHERE p.oid=pg_catalog.to_regprocedure('enrollment_execution.audit_execution_profile_structure(uuid)')
          AND p.proowner=owner_oid AND l.lanname='plpgsql' AND p.prokind='f' AND NOT p.prosecdef
          AND p.provolatile='s' AND p.proparallel='u' AND NOT p.proisstrict AND NOT p.proleakproof AND p.prosupport=0
          AND p.proretset AND p.prorettype=2249 AND p.pronargs=1 AND p.proargtypes::text='2950'
          AND p.proallargtypes IS NOT DISTINCT FROM ARRAY[2950,16,25,21]::oid[]
          AND p.proargnames IS NOT DISTINCT FROM ARRAY['p_environment','is_valid','diagnostic_code','profile_version']::text[]
          AND p.proargmodes IS NOT DISTINCT FROM ARRAY['i','t','t','t']::"char"[]
          AND p.pronargdefaults=0 AND p.proargdefaults IS NULL AND p.provariadic=0 AND p.protrftypes IS NULL
          AND p.probin IS NULL AND p.prosqlbody IS NULL
          AND p.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp','row_security=on']
          AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.replace(p.prosrc,E'\r\n',E'\n'),'UTF8')),'hex')=expected_structure_hash
          AND (SELECT count(*)=1 AND bool_and(acl.grantor=owner_oid AND acl.grantee=owner_oid
              AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable)
            FROM pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) acl))
       OR (SELECT count(*) FROM pg_catalog.pg_proc p WHERE p.pronamespace=pg_catalog.to_regnamespace('enrollment_execution')
           AND p.proname='audit_execution_profile_structure')<>1 THEN
        RETURN QUERY SELECT false,'ProfileDrift'::text,4::smallint;
        RETURN;
    END IF;
    SELECT count(*),count(*) FILTER(WHERE result.is_valid IS TRUE AND result.diagnostic_code='None' AND result.profile_version=4)
      INTO row_count,valid_count FROM enrollment_execution.audit_execution_profile_structure(p_environment) result;
    IF row_count<>1 OR valid_count<>1 THEN
        RETURN QUERY SELECT false,'ProfileDrift'::text,4::smallint;
        RETURN;
    END IF;
    ready:=enrollment_execution.profile4_ready() IS TRUE;
    RETURN QUERY SELECT ready,CASE WHEN ready THEN 'None'::text ELSE 'ProfileDrift'::text END,4::smallint;
END
$function$;
