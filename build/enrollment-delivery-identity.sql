-- Staged source only: not included by a production installer until exact profile4
-- attestation and compatibility verification are complete. Caller holds the profile lock.
CREATE FUNCTION public.api_database_session() RETURNS boolean
LANGUAGE sql STABLE PARALLEL UNSAFE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET row_security=on AS $function$
    SELECT EXISTS(SELECT 1 FROM public."DirectoryDatabaseBindings" binding
      WHERE binding."LoginRole"=SESSION_USER AND binding."Purpose"='Api'
        AND binding."ContractVersion"=1 AND binding."EnvironmentId" IS NULL
        AND binding."PrincipalId" IS NULL)
$function$;
ALTER FUNCTION public.api_database_session() OWNER TO :"expected_table_owner_role";
REVOKE ALL ON FUNCTION public.api_database_session() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.api_database_session() TO PUBLIC;

CREATE POLICY enrollment_identity_principals_owner ON public."Principals"
    FOR ALL TO :"expected_table_owner_role" USING(true) WITH CHECK(true);
CREATE POLICY enrollment_identity_sessions_owner ON public."Sessions"
    FOR ALL TO :"expected_table_owner_role" USING(true) WITH CHECK(true);

-- Direct API access preserves pre-authentication principal lookup and session lifecycle.
-- A different SECURITY DEFINER context cannot inherit the API session's broad visibility.
CREATE POLICY enrollment_identity_principals_api_read ON public."Principals"
    FOR SELECT TO PUBLIC USING(CURRENT_USER=SESSION_USER AND public.api_database_session());
CREATE POLICY enrollment_identity_sessions_api ON public."Sessions"
    FOR ALL TO PUBLIC USING(CURRENT_USER=SESSION_USER AND public.api_database_session())
    WITH CHECK(CURRENT_USER=SESSION_USER AND public.api_database_session());

-- PostgreSQL row locks require both SELECT and UPDATE policies. Table ACLs continue
-- to deny direct API principal mutation; only the pinned plan-lock helper has UPDATE.
CREATE POLICY enrollment_identity_principals_plan_read ON public."Principals"
    FOR SELECT TO :"enrollment_plan_lock_owner_role" USING(public.api_database_session());
CREATE POLICY enrollment_identity_principals_plan_lock ON public."Principals"
    FOR UPDATE TO :"enrollment_plan_lock_owner_role" USING(public.api_database_session())
    WITH CHECK(false);

CREATE POLICY enrollment_identity_principals_execution_read_allow ON public."Principals"
    AS PERMISSIVE FOR SELECT TO :"execution_definer_role"
    USING("Id" IN(nullif(current_setting('app.execution_requester_id',true),'')::uuid,
      nullif(current_setting('app.execution_approver_id',true),'')::uuid));
CREATE POLICY enrollment_identity_principals_execution_read_limit ON public."Principals"
    AS RESTRICTIVE FOR SELECT TO :"execution_definer_role"
    USING("Id" IN(nullif(current_setting('app.execution_requester_id',true),'')::uuid,
      nullif(current_setting('app.execution_approver_id',true),'')::uuid));
CREATE POLICY enrollment_identity_principals_execution_lock_allow ON public."Principals"
    AS PERMISSIVE FOR UPDATE TO :"execution_definer_role"
    USING("Id" IN(nullif(current_setting('app.execution_requester_id',true),'')::uuid,
      nullif(current_setting('app.execution_approver_id',true),'')::uuid))
    WITH CHECK(false);
CREATE POLICY enrollment_identity_principals_execution_lock_limit ON public."Principals"
    AS RESTRICTIVE FOR UPDATE TO :"execution_definer_role"
    USING("Id" IN(nullif(current_setting('app.execution_requester_id',true),'')::uuid,
      nullif(current_setting('app.execution_approver_id',true),'')::uuid))
    WITH CHECK(false);

-- Install all owner/API/plan/execution/delivery policies before turning enforcement on.
ALTER TABLE public."Principals" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."Principals" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."Sessions" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."Sessions" FORCE ROW LEVEL SECURITY;
