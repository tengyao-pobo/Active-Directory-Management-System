-- Run by a DBA against the intended database after migrations.
-- Create the LOGIN role separately through your secret-management procedure.
-- This script never embeds a password. psql: -v runtime_role=your_role -f this-file
GRANT CONNECT ON DATABASE :DBNAME TO :"runtime_role";
GRANT USAGE ON SCHEMA public TO :"runtime_role";
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM :"runtime_role";
GRANT EXECUTE ON FUNCTION public.has_environment_membership(uuid, uuid) TO :"runtime_role";
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO :"runtime_role";
REVOKE ALL ON "__EFMigrationsHistory" FROM :"runtime_role";
REVOKE UPDATE, DELETE, TRUNCATE ON "Audit", "SecurityEvents" FROM :"runtime_role";
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON "Principals" FROM :"runtime_role";
REVOKE INSERT, DELETE, TRUNCATE ON "LocalCredentials" FROM :"runtime_role";
REVOKE INSERT, DELETE, TRUNCATE ON "EnrollmentGrants" FROM :"runtime_role";
REVOKE TRUNCATE ON ALL TABLES IN SCHEMA public FROM :"runtime_role";
-- Role must be NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE and not table owner.
