-- DBA only. Create a separate LOGIN role with an externally managed credential.
-- Never reuse the API runtime, migration owner, or a privileged AD account.
-- psql -v connector_role=console_connector -v environment_id=UUID -v principal_id=UUID -f build/provision-connector.sql
GRANT CONNECT ON DATABASE :DBNAME TO :"connector_role";
GRANT USAGE ON SCHEMA public TO :"connector_role";
REVOKE CREATE ON SCHEMA public FROM :"connector_role";
GRANT EXECUTE ON FUNCTION public.has_environment_membership(uuid, uuid) TO :"connector_role";
INSERT INTO "DirectoryDatabaseBindings" ("LoginRole","Purpose","EnvironmentId","PrincipalId")
    VALUES (:'connector_role','Connector',:'environment_id'::uuid,:'principal_id'::uuid)
    ON CONFLICT ("LoginRole") DO UPDATE SET "Purpose"='Connector',"EnvironmentId"=EXCLUDED."EnvironmentId","PrincipalId"=EXCLUDED."PrincipalId";
GRANT EXECUTE ON FUNCTION public.directory_database_access(uuid,uuid), public.directory_connector_scope(uuid,uuid) TO :"connector_role";
GRANT SELECT, INSERT, UPDATE, DELETE ON "DirectoryObjects", "DirectorySync" TO :"connector_role";
GRANT INSERT ON "Audit" TO :"connector_role";
REVOKE ALL ON "DirectoryDatabaseBindings", "Memberships", "Principals" FROM :"connector_role";
REVOKE TRUNCATE ON ALL TABLES IN SCHEMA public FROM :"connector_role";
-- Provision a dedicated enabled platform principal with active environment membership offline.
-- Assign no interactive roles, credentials, or sessions to that principal.
