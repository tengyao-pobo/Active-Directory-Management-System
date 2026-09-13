-- Unconsumed restricted-owner forward fragment. Preserve FORCE RLS and the helper's OID/ACL.
DO $preflight$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles r
   WHERE r.rolname=CURRENT_USER AND r.rolname=SESSION_USER AND r.rolcanlogin
     AND NOT(r.rolsuper OR r.rolbypassrls OR r.rolcreatedb OR r.rolcreaterole OR r.rolinherit OR r.rolreplication)
     AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member=r.oid OR m.roleid=r.oid)
     AND (SELECT relowner FROM pg_catalog.pg_class WHERE oid=pg_catalog.to_regclass('public."Memberships"'))=r.oid
     AND (SELECT proowner FROM pg_catalog.pg_proc WHERE oid=pg_catalog.to_regprocedure('public.has_environment_membership(uuid,uuid)'))=r.oid) THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Membership adaptation requires the restricted final owner.';
 END IF;
END
$preflight$;
CREATE OR REPLACE FUNCTION public.has_environment_membership(p_environment_id uuid, p_principal_id uuid)
RETURNS boolean LANGUAGE sql STABLE STRICT SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET row_security=on AS $function$
    SELECT EXISTS (SELECT 1 FROM public."Memberships" m
        JOIN public."Principals" p ON p."Id"=m."PrincipalId"
        WHERE m."EnvironmentId"=p_environment_id AND m."PrincipalId"=p_principal_id AND m."Active" AND p."Enabled")
$function$;
REVOKE ALL ON FUNCTION public.has_environment_membership(uuid,uuid) FROM PUBLIC;
CREATE POLICY enrollment_profile4_membership_owner_select ON public."Memberships"
AS PERMISSIVE FOR SELECT TO CURRENT_USER USING(true);
