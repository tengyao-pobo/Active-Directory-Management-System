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
 EXECUTE 'SELECT NOT EXISTS(SELECT 1 FROM agent_private.agent_capability_roles WHERE role_name=$1 AND (capability<>$2 OR role_kind<>$3))' INTO v_valid USING :'agent_projection_role'::name,'Projection','Runtime';
 IF NOT v_valid THEN RAISE EXCEPTION USING ERRCODE='22012';END IF;
 EXECUTE 'SELECT count(*)=1 FROM agent_private.agent_capability_roles WHERE role_name=$1 AND capability=$2 AND role_kind=''Definer''' INTO v_valid USING :'agent_projection_definer_role'::name,'Projection';
 IF NOT v_valid THEN RAISE EXCEPTION USING ERRCODE='22012';END IF;
 EXECUTE 'INSERT INTO agent_private.agent_capability_roles(role_name,capability,role_kind) VALUES($1,$2,$3) ON CONFLICT(role_name) DO NOTHING' USING :'agent_projection_role'::name,'Projection','Runtime';
 EXECUTE 'SELECT count(*)=1 FROM agent_private.agent_capability_roles WHERE role_name=$1 AND capability=$2 AND role_kind=$3' INTO v_valid USING :'agent_projection_role'::name,'Projection','Runtime';
 IF NOT v_valid THEN RAISE EXCEPTION USING ERRCODE='22012';END IF;
END
$capability_registry_reservation$;

SELECT 1 / pg_catalog.count(*) AS roles_have_no_platform_grant_binding FROM (SELECT 1 WHERE
    agent_private.platform_grant_role_is_unbound(:'agent_table_owner_role'::name) AND
    agent_private.platform_grant_role_is_unbound(:'agent_projection_definer_role'::name) AND
    agent_private.platform_grant_role_is_unbound(:'agent_projection_role'::name)) checked;

SELECT 1/pg_catalog.count(*) AS roles_are_distinct FROM (SELECT 1 WHERE
 :'agent_table_owner_role'<>:'agent_projection_definer_role' AND
 :'agent_table_owner_role'<>:'agent_projection_role' AND
 :'agent_projection_definer_role'<>:'agent_projection_role') checked;

SELECT 1/pg_catalog.count(*) AS roles_are_not_runtime_bindings FROM (SELECT 1 WHERE
 NOT EXISTS(SELECT 1 FROM agent_private.agent_database_bindings binding WHERE binding.login_role=:'agent_projection_role'::name) AND
 NOT EXISTS(SELECT 1 FROM agent_private.enrollment_database_bindings binding WHERE binding.login_role=:'agent_projection_role'::name) AND
 NOT EXISTS(SELECT 1 FROM agent_private.agent_database_bindings binding WHERE binding.login_role=:'agent_projection_definer_role'::name) AND
 NOT EXISTS(SELECT 1 FROM agent_private.enrollment_database_bindings binding WHERE binding.login_role=:'agent_projection_definer_role'::name) AND
 NOT EXISTS(SELECT 1 FROM agent_private.agent_projection_database_bindings binding WHERE binding.login_role=:'agent_projection_definer_role'::name) AND
 NOT EXISTS(SELECT 1 FROM agent_private.agent_projection_database_bindings binding WHERE binding.login_role=:'agent_projection_role'::name AND
  (binding.environment_id<>:'environment_id'::uuid OR binding.purpose<>'ReadDeviceProjection'))) checked;

SELECT 1/pg_catalog.count(*) AS ownership_is_bounded FROM (SELECT 1 WHERE
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database database JOIN pg_catalog.pg_roles role ON role.oid=database.datdba WHERE role.rolname=:'agent_projection_role') AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc function JOIN pg_catalog.pg_namespace namespace ON namespace.oid=function.pronamespace
  JOIN pg_catalog.pg_roles role ON role.oid=function.proowner WHERE namespace.nspname='agent_private' AND role.rolname=:'agent_projection_role') AND
 (SELECT pg_catalog.count(*)=3 AND pg_catalog.bool_and(
   (function.proname='read_current_bitlocker_projection' AND pg_catalog.pg_get_function_identity_arguments(function.oid)='p_environment_id uuid, p_directory_object_id uuid') OR
   (function.proname='read_current_inventory_projection' AND pg_catalog.pg_get_function_identity_arguments(function.oid)='p_environment_id uuid, p_directory_object_id uuid') OR
   (function.proname='audit_projection_privileges' AND pg_catalog.pg_get_function_identity_arguments(function.oid)='p_expected_environment_id uuid, p_expected_table_owner name, p_expected_function_owner name'))
  FROM pg_catalog.pg_proc function JOIN pg_catalog.pg_namespace namespace ON namespace.oid=function.pronamespace
  JOIN pg_catalog.pg_roles role ON role.oid=function.proowner WHERE namespace.nspname='agent_private' AND role.rolname=:'agent_projection_definer_role')) checked;

ALTER ROLE :"agent_projection_definer_role" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
ALTER ROLE :"agent_projection_role" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
GRANT CONNECT ON DATABASE :DBNAME TO :"agent_projection_role";
GRANT USAGE ON SCHEMA agent_private TO :"agent_projection_role";
REVOKE CREATE ON SCHEMA agent_private FROM :"agent_projection_role", :"agent_projection_definer_role";
REVOKE ALL ON ALL TABLES IN SCHEMA agent_private FROM :"agent_projection_role";
REVOKE ALL ON ALL SEQUENCES IN SCHEMA agent_private FROM :"agent_projection_role";
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA agent_private FROM :"agent_projection_role";
GRANT EXECUTE ON FUNCTION agent_private.read_current_bitlocker_projection(uuid,uuid),
 agent_private.read_current_inventory_projection(uuid,uuid),
 agent_private.audit_projection_privileges(uuid,name,name) TO :"agent_projection_role";

INSERT INTO agent_private.agent_projection_database_bindings(login_role,environment_id,purpose)
VALUES(:'agent_projection_role'::name,:'environment_id'::uuid,'ReadDeviceProjection') ON CONFLICT(login_role) DO NOTHING;
SELECT 1/pg_catalog.count(*) AS exact_binding_exists FROM agent_private.agent_projection_database_bindings binding WHERE
 binding.login_role=:'agent_projection_role'::name AND binding.environment_id=:'environment_id'::uuid AND binding.purpose='ReadDeviceProjection';

COMMIT;
