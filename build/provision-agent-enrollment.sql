\set ON_ERROR_STOP on

BEGIN;

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
