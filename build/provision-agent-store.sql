\set ON_ERROR_STOP on

-- Roles are created separately by the DBA with externally managed credentials.
SELECT 1 / pg_catalog.count(*) AS roles_are_distinct
FROM (SELECT 1 WHERE :'agent_definer_role' <> :'agent_ingest_role') distinction;
ALTER ROLE :"agent_definer_role" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
ALTER ROLE :"agent_ingest_role" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;

GRANT CONNECT ON DATABASE :DBNAME TO :"agent_ingest_role";
GRANT USAGE ON SCHEMA agent_private TO :"agent_ingest_role";
REVOKE CREATE ON SCHEMA agent_private FROM :"agent_ingest_role";
REVOKE ALL ON ALL TABLES IN SCHEMA agent_private FROM :"agent_ingest_role";
REVOKE ALL ON ALL SEQUENCES IN SCHEMA agent_private FROM :"agent_ingest_role";
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA agent_private FROM :"agent_ingest_role";
GRANT EXECUTE ON FUNCTION agent_private.ingest_attested_envelope(bytea,integer,uuid,bigint,bigint,uuid,bigint,bytea,text,text)
    TO :"agent_ingest_role";
GRANT EXECUTE ON FUNCTION agent_private.audit_ingest_privileges(name) TO :"agent_ingest_role";

INSERT INTO agent_private.agent_database_bindings(login_role, environment_id, purpose)
VALUES (:'agent_ingest_role'::name, :'environment_id'::uuid, 'Ingest')
ON CONFLICT (login_role) DO NOTHING;

-- Re-provisioning is idempotent only for the exact authorization binding.
-- Environment changes require a separate, explicitly reviewed rebind workflow.
SELECT 1 / pg_catalog.count(*) AS exact_binding_exists
FROM agent_private.agent_database_bindings binding
WHERE binding.login_role = :'agent_ingest_role'::name
  AND binding.environment_id = :'environment_id'::uuid
  AND binding.purpose = 'Ingest';

-- Startup privilege audit must additionally confirm this login has no role memberships,
-- direct table/sequence privileges, elevated attributes, or function-owner mismatch.
