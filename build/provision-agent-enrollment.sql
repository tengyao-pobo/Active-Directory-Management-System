\set ON_ERROR_STOP on

BEGIN;
-- Optional legacy mode remains available while the v2 marker and registry are both absent.
-- Once v2 exists, role identity is reserved transactionally before any ALTER or GRANT.
DO $capability_registry_reservation$
DECLARE v_marker regprocedure:=pg_catalog.to_regprocedure('agent_private.agent_capability_isolation_profile()');v_registry regclass:=pg_catalog.to_regclass('agent_private.agent_capability_roles');v_valid boolean;
BEGIN
 IF (v_marker IS NULL)<>(v_registry IS NULL) THEN RAISE EXCEPTION USING ERRCODE='22012';END IF;
 IF v_marker IS NULL THEN RETURN;END IF;
 SELECT marker.proowner=namespace.nspowner AND marker.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='sql') AND NOT marker.prosecdef AND marker.prokind='f' AND NOT marker.proretset AND marker.prorettype='smallint'::pg_catalog.regtype AND marker.pronargs=0 AND marker.proargnames IS NULL AND marker.proconfig=ARRAY['search_path=pg_catalog, agent_private, pg_temp']::text[] AND pg_catalog.btrim(marker.prosrc)=pg_catalog.btrim('SELECT 2::smallint') INTO v_valid FROM pg_catalog.pg_proc marker JOIN pg_catalog.pg_namespace namespace ON namespace.oid=marker.pronamespace WHERE marker.oid=v_marker;
 IF NOT COALESCE(v_valid,false) THEN RAISE EXCEPTION USING ERRCODE='22012';END IF;
 EXECUTE 'SELECT NOT EXISTS(SELECT 1 FROM agent_private.agent_capability_roles WHERE role_name=$1 AND (capability<>$2 OR role_kind<>$3))' INTO v_valid USING :'agent_enroll_role'::name,'Enrollment','Runtime';
 IF NOT v_valid THEN RAISE EXCEPTION USING ERRCODE='22012';END IF;
 EXECUTE 'SELECT NOT EXISTS(SELECT 1 FROM agent_private.agent_capability_roles WHERE role_name=$1 AND (capability<>$2 OR role_kind<>$3))' INTO v_valid USING :'agent_issue_role'::name,'Enrollment','Runtime';
 IF NOT v_valid THEN RAISE EXCEPTION USING ERRCODE='22012';END IF;
 EXECUTE 'SELECT count(*)=1 FROM agent_private.agent_capability_roles WHERE role_name=$1 AND capability=$2 AND role_kind=''Definer''' INTO v_valid USING :'agent_enrollment_definer_role'::name,'Enrollment';
 IF NOT v_valid THEN RAISE EXCEPTION USING ERRCODE='22012';END IF;
 EXECUTE 'INSERT INTO agent_private.agent_capability_roles(role_name,capability,role_kind) VALUES($1,$2,$3) ON CONFLICT(role_name) DO NOTHING' USING :'agent_enroll_role'::name,'Enrollment','Runtime';
 EXECUTE 'INSERT INTO agent_private.agent_capability_roles(role_name,capability,role_kind) VALUES($1,$2,$3) ON CONFLICT(role_name) DO NOTHING' USING :'agent_issue_role'::name,'Enrollment','Runtime';
 EXECUTE 'SELECT count(*)=1 FROM agent_private.agent_capability_roles WHERE role_name=$1 AND capability=$2 AND role_kind=$3' INTO v_valid USING :'agent_enroll_role'::name,'Enrollment','Runtime';
 IF NOT v_valid THEN RAISE EXCEPTION USING ERRCODE='22012';END IF;
 EXECUTE 'SELECT count(*)=1 FROM agent_private.agent_capability_roles WHERE role_name=$1 AND capability=$2 AND role_kind=$3' INTO v_valid USING :'agent_issue_role'::name,'Enrollment','Runtime';
 IF NOT v_valid THEN RAISE EXCEPTION USING ERRCODE='22012';END IF;
END
$capability_registry_reservation$;

SELECT 1 / pg_catalog.count(*) AS roles_have_no_platform_grant_binding FROM (SELECT 1 WHERE
    agent_private.platform_grant_role_is_unbound(:'agent_table_owner_role'::name) AND
    agent_private.platform_grant_role_is_unbound(:'agent_enrollment_definer_role'::name) AND
    agent_private.platform_grant_role_is_unbound(:'agent_enroll_role'::name) AND
    agent_private.platform_grant_role_is_unbound(:'agent_issue_role'::name)) checked;

SELECT 1 / pg_catalog.count(*) AS roles_are_distinct
FROM (SELECT 1 WHERE :'agent_table_owner_role' <> :'agent_enrollment_definer_role'
  AND :'agent_table_owner_role' <> :'agent_enroll_role'
  AND :'agent_table_owner_role' <> :'agent_issue_role'
  AND :'agent_enroll_role' <> :'agent_issue_role'
  AND :'agent_enroll_role' <> :'agent_enrollment_definer_role'
  AND :'agent_issue_role' <> :'agent_enrollment_definer_role') distinction;

ALTER ROLE :"agent_enrollment_definer_role" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
ALTER ROLE :"agent_enroll_role" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
ALTER ROLE :"agent_issue_role" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;

GRANT CONNECT ON DATABASE :DBNAME TO :"agent_enroll_role", :"agent_issue_role";
GRANT USAGE ON SCHEMA agent_private TO :"agent_enroll_role", :"agent_issue_role";
REVOKE CREATE ON SCHEMA agent_private FROM :"agent_enroll_role", :"agent_issue_role";
REVOKE ALL ON ALL TABLES IN SCHEMA agent_private FROM :"agent_enroll_role", :"agent_issue_role";
REVOKE ALL ON ALL SEQUENCES IN SCHEMA agent_private FROM :"agent_enroll_role", :"agent_issue_role";
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA agent_private FROM :"agent_enroll_role", :"agent_issue_role";

GRANT EXECUTE ON FUNCTION agent_private.submit_or_recover_enrollment(bytea,uuid,uuid,bytea,bytea,bytea,integer)
    TO :"agent_enroll_role";
GRANT EXECUTE ON FUNCTION agent_private.claim_enrollment_issuance(uuid,uuid),
    agent_private.complete_enrollment_issuance(uuid,uuid,uuid,uuid,uuid,uuid,bigint,integer,bytea,bytea[],bytea,bytea,bytea,timestamptz,timestamptz),
    agent_private.defer_enrollment_issuance(uuid,uuid,integer),
    agent_private.mark_enrollment_issuance_unknown(uuid,uuid),
    agent_private.fail_enrollment_issuance_definitively(uuid,uuid)
    TO :"agent_issue_role";
GRANT EXECUTE ON FUNCTION agent_private.audit_enrollment_privileges(name,name,text)
    TO :"agent_enroll_role", :"agent_issue_role";

INSERT INTO agent_private.enrollment_database_bindings(login_role,environment_id,purpose)
VALUES (:'agent_enroll_role'::name,:'environment_id'::uuid,'Enroll'),
       (:'agent_issue_role'::name,:'environment_id'::uuid,'Issue')
ON CONFLICT (login_role) DO NOTHING;

SELECT 1 / pg_catalog.count(*) AS exact_enroll_binding_exists
FROM agent_private.enrollment_database_bindings binding
WHERE binding.login_role=:'agent_enroll_role'::name AND binding.environment_id=:'environment_id'::uuid AND binding.purpose='Enroll';
SELECT 1 / pg_catalog.count(*) AS exact_issue_binding_exists
FROM agent_private.enrollment_database_bindings binding
WHERE binding.login_role=:'agent_issue_role'::name AND binding.environment_id=:'environment_id'::uuid AND binding.purpose='Issue';

-- Grant creation remains table-owner-only until a reviewed human authorization function exists.

COMMIT;
