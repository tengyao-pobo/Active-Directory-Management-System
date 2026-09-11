\set ON_ERROR_STOP on
BEGIN;

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
