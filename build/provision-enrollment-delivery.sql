\set ON_ERROR_STOP on
BEGIN;
SELECT pg_catalog.pg_advisory_xact_lock(1162235478,1);
SELECT pg_catalog.set_config('app.delivery_install_status_runtime',:'status_runtime_role',true),
 pg_catalog.set_config('app.delivery_install_runtime',:'delivery_runtime_role',true),
 pg_catalog.set_config('app.delivery_install_definer',:'delivery_definer_role',true),
 pg_catalog.set_config('app.delivery_install_owner',:'expected_table_owner_role',true),
 pg_catalog.set_config('app.delivery_install_environment',:'expected_environment_id',true);

DO $preflight$
DECLARE owner_oid oid; definer_oid oid; status_oid oid; delivery_oid oid; environment_id uuid; audit_row record;
BEGIN
 environment_id:=current_setting('app.delivery_install_environment')::uuid;
 SELECT oid INTO owner_oid FROM pg_catalog.pg_roles WHERE rolname=current_setting('app.delivery_install_owner');
 SELECT oid INTO definer_oid FROM pg_catalog.pg_roles WHERE rolname=current_setting('app.delivery_install_definer');
 SELECT oid INTO status_oid FROM pg_catalog.pg_roles WHERE rolname=current_setting('app.delivery_install_status_runtime');
 SELECT oid INTO delivery_oid FROM pg_catalog.pg_roles WHERE rolname=current_setting('app.delivery_install_runtime');
 IF environment_id='00000000-0000-0000-0000-000000000000'::uuid
  OR owner_oid IS NULL OR owner_oid<>CURRENT_USER::regrole::oid
  OR definer_oid IS NULL OR status_oid IS NULL OR delivery_oid IS NULL
  OR owner_oid IN(definer_oid,status_oid,delivery_oid) OR definer_oid IN(status_oid,delivery_oid)
  OR status_oid=delivery_oid
  OR NOT EXISTS(SELECT 1 FROM public."Environments" WHERE "Id"=environment_id)
  OR NOT EXISTS(SELECT 1 FROM enrollment_execution.role_reservations reservation
      WHERE reservation.role_oid=definer_oid AND reservation.role_name=current_setting('app.delivery_install_definer')::name
        AND reservation.capability='EnrollmentGrantDelivery' AND reservation.role_kind='DeliveryDefiner'
        AND reservation.reservation_schema_version=1)
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_roles role WHERE role.oid IN(definer_oid,status_oid,delivery_oid)
      AND (role.rolsuper OR role.rolbypassrls OR role.rolcreatedb OR role.rolcreaterole OR role.rolinherit OR role.rolreplication
        OR role.rolcanlogin IS DISTINCT FROM (role.oid IN(status_oid,delivery_oid))))
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members membership
      WHERE membership.roleid IN(definer_oid,status_oid,delivery_oid) OR membership.member IN(definer_oid,status_oid,delivery_oid))
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_database database_row WHERE database_row.datdba IN(definer_oid,status_oid,delivery_oid))
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_namespace namespace_row WHERE namespace_row.nspowner IN(definer_oid,status_oid,delivery_oid))
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_class relation WHERE relation.relowner IN(definer_oid,status_oid,delivery_oid))
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc function_row WHERE function_row.proowner IN(status_oid,delivery_oid))
  OR EXISTS(SELECT 1 FROM enrollment_execution.role_reservations reservation
      WHERE reservation.role_name IN(current_setting('app.delivery_install_status_runtime')::name,
          current_setting('app.delivery_install_runtime')::name)
         OR reservation.role_oid IN(status_oid,delivery_oid))
  OR EXISTS(SELECT 1 FROM public."DirectoryDatabaseBindings" binding
      WHERE binding."LoginRole" IN(current_setting('app.delivery_install_status_runtime'),
          current_setting('app.delivery_install_runtime')))
  OR EXISTS(SELECT 1 FROM enrollment_execution.role_reservations reservation
      WHERE reservation.role_name IN(current_setting('app.delivery_install_definer')::name,
          current_setting('app.delivery_install_status_runtime')::name,current_setting('app.delivery_install_runtime')::name)
        AND NOT(reservation.role_oid=definer_oid AND reservation.role_kind='DeliveryDefiner'
          AND reservation.capability='EnrollmentGrantDelivery'))
  OR pg_catalog.has_schema_privilege(current_setting('app.delivery_install_status_runtime'),'public','CREATE')
  OR pg_catalog.has_schema_privilege(current_setting('app.delivery_install_status_runtime'),'enrollment_execution','CREATE')
  OR pg_catalog.has_schema_privilege(current_setting('app.delivery_install_runtime'),'public','CREATE')
  OR pg_catalog.has_schema_privilege(current_setting('app.delivery_install_runtime'),'enrollment_execution','CREATE')
  OR pg_catalog.has_database_privilege(current_setting('app.delivery_install_status_runtime'),pg_catalog.current_database(),'CREATE')
  OR pg_catalog.has_database_privilege(current_setting('app.delivery_install_runtime'),pg_catalog.current_database(),'CREATE') THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Enrollment delivery provision preflight failed.';
 END IF;
 SELECT * INTO STRICT audit_row FROM enrollment_execution.audit_execution_privileges(environment_id);
 IF audit_row.is_valid IS NOT TRUE OR audit_row.diagnostic_code<>'None' OR audit_row.profile_version<>4 THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Enrollment delivery source profile is invalid.';
 END IF;
END
$preflight$;

INSERT INTO enrollment_execution.role_reservations(role_name,role_oid,capability,role_kind,reservation_schema_version)
 SELECT :'status_runtime_role'::name,oid,'EnrollmentGrantDelivery','StatusRuntime',1
 FROM pg_catalog.pg_roles WHERE rolname=:'status_runtime_role';
INSERT INTO enrollment_execution.role_reservations(role_name,role_oid,capability,role_kind,reservation_schema_version)
 SELECT :'delivery_runtime_role'::name,oid,'EnrollmentGrantDelivery','DeliveryRuntime',1
 FROM pg_catalog.pg_roles WHERE rolname=:'delivery_runtime_role';
INSERT INTO public."DirectoryDatabaseBindings"("LoginRole","Purpose","ContractVersion","EnvironmentId","PrincipalId")
 VALUES(:'status_runtime_role','EnrollmentGrantStatusRefresh',1,:'expected_environment_id'::uuid,NULL);
INSERT INTO public."DirectoryDatabaseBindings"("LoginRole","Purpose","ContractVersion","EnvironmentId","PrincipalId")
 VALUES(:'delivery_runtime_role','EnrollmentGrantDelivery',1,:'expected_environment_id'::uuid,NULL);

GRANT CONNECT ON DATABASE :"DBNAME" TO :"status_runtime_role",:"delivery_runtime_role";
GRANT USAGE ON SCHEMA enrollment_execution TO :"status_runtime_role",:"delivery_runtime_role";
GRANT EXECUTE ON FUNCTION enrollment_execution.read_grant_status_receipt(uuid,uuid),
 enrollment_execution.append_grant_status_observation(uuid,uuid,uuid,text,text,timestamptz,timestamptz,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea),
 enrollment_execution.audit_delivery_privileges(uuid) TO :"status_runtime_role";
GRANT EXECUTE ON FUNCTION enrollment_execution.read_grant_delivery(uuid,uuid,uuid,text),
 enrollment_execution.acknowledge_grant_delivery(uuid,uuid,uuid,text,bytea,bytea),
 enrollment_execution.audit_delivery_privileges(uuid) TO :"delivery_runtime_role";
REVOKE CREATE ON SCHEMA public,enrollment_execution FROM :"status_runtime_role",:"delivery_runtime_role";

DO $postflight$
DECLARE audit_row record;
BEGIN
 SELECT * INTO STRICT audit_row FROM enrollment_execution.audit_delivery_privileges(
     current_setting('app.delivery_install_environment')::uuid);
 IF audit_row.is_valid IS NOT TRUE OR audit_row.diagnostic_code<>'None' OR audit_row.profile_version<>4 THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Enrollment delivery provision postflight failed.';
 END IF;
END
$postflight$;
COMMIT;
