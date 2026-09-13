-- Unconsumed independent template. Render the one audit-body hash before installation.
CREATE FUNCTION enrollment_execution.guard_profile4_publication() RETURNS trigger
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET row_security=on AS $function$
DECLARE
    expected_runtime_hash constant text := '4a17d8703cafed7884df3b5621032ce9e4326f4973b845360c6cc6fccab1f4ee';
    owner_oid oid;
    audit_rows bigint;
    valid_rows bigint;
BEGIN
    IF TG_OP<>'INSERT' OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' OR TG_NARGS<>0
        OR TG_NAME<>'enrollment_grant_operation_00_publication'
        OR TG_RELID IS DISTINCT FROM pg_catalog.to_regclass('public."EnrollmentGrantOperations"')
        OR pg_catalog.current_setting('session_replication_role')<>'origin' THEN
        RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Enrollment grant publication is unavailable.';
    END IF;
    -- Arbitrary direct SQL may already hold relation locks. Never wait for the installer.
    IF NOT pg_catalog.pg_try_advisory_xact_lock_shared(1162235478,1) THEN
        RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Enrollment grant publication is unavailable.';
    END IF;
    SELECT min(relation.relowner) INTO owner_oid FROM pg_catalog.pg_class relation
      WHERE relation.oid IN(pg_catalog.to_regclass('public."Environments"'),pg_catalog.to_regclass('public."EnrollmentGrantOperations"'))
      HAVING count(*)=2 AND count(DISTINCT relation.relowner)=1
        AND bool_and(relation.relowner=CURRENT_USER::regrole::oid AND relation.relkind='r'
          AND relation.relpersistence='p' AND NOT relation.relispartition);
    IF owner_oid IS NULL OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
        WHERE p.oid=pg_catalog.to_regprocedure('enrollment_execution.audit_execution_privileges(uuid)')
          AND p.proowner=owner_oid AND l.lanname='plpgsql' AND p.prokind='f' AND p.prosecdef
          AND p.provolatile='v' AND p.proparallel='u' AND NOT p.proisstrict AND NOT p.proleakproof AND p.prosupport=0
          AND p.proretset AND p.prorettype=2249 AND p.pronargs=1 AND p.proargtypes::text='2950'
          AND p.proallargtypes IS NOT DISTINCT FROM ARRAY[2950,16,25,21]::oid[]
          AND p.proargnames IS NOT DISTINCT FROM ARRAY['p_environment','is_valid','diagnostic_code','profile_version']::text[]
          AND p.proargmodes IS NOT DISTINCT FROM ARRAY['i','t','t','t']::"char"[]
          AND p.pronargdefaults=0 AND p.proargdefaults IS NULL AND p.provariadic=0 AND p.protrftypes IS NULL
          AND p.probin IS NULL AND p.prosqlbody IS NULL
          AND p.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp','row_security=on']
          AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.replace(p.prosrc,E'\r\n',E'\n'),'UTF8')),'hex')=expected_runtime_hash)
       OR (SELECT count(*) FROM pg_catalog.pg_proc p WHERE p.pronamespace=pg_catalog.to_regnamespace('enrollment_execution')
           AND p.proname='audit_execution_privileges')<>1 THEN
        RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Enrollment grant publication is unavailable.';
    END IF;
    -- The pinned runtime body first attests maintenance, including the exact audit ACL,
    -- then locks readiness FOR SHARE so a stale SERIALIZABLE snapshot raises 40001.
    SELECT count(*),count(*) FILTER(WHERE result.is_valid IS TRUE AND result.diagnostic_code='None' AND result.profile_version=4)
      INTO audit_rows,valid_rows FROM enrollment_execution.audit_execution_privileges(NEW."EnvironmentId") result;
    IF audit_rows<>1 OR valid_rows<>1 THEN
        RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Enrollment grant publication is unavailable.';
    END IF;
    -- Maintenance attests the sole API binding and its safe role/parameter profile.
    -- An unrelated role with a drifted INSERT grant must never publish through this guard.
    IF NOT EXISTS(SELECT 1 FROM public."DirectoryDatabaseBindings" binding
        WHERE binding."Purpose"='Api' AND binding."ContractVersion"=1
          AND binding."EnvironmentId" IS NULL AND binding."PrincipalId" IS NULL
          AND binding."LoginRole"=SESSION_USER::name) THEN
        RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Enrollment grant publication is unavailable.';
    END IF;
    RETURN NEW;
END
$function$;
REVOKE ALL ON FUNCTION enrollment_execution.guard_profile4_publication() FROM PUBLIC;
CREATE TRIGGER enrollment_grant_operation_00_publication BEFORE INSERT ON public."EnrollmentGrantOperations"
FOR EACH ROW EXECUTE FUNCTION enrollment_execution.guard_profile4_publication();
ALTER TABLE public."EnrollmentGrantOperations" ENABLE ALWAYS TRIGGER enrollment_grant_operation_00_publication;
