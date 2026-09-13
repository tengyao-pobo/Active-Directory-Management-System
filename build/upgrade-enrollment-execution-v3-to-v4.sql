\set ON_ERROR_STOP on
BEGIN;
SELECT pg_catalog.pg_advisory_xact_lock(1162235478,1);
SELECT pg_catalog.set_config('app.delivery_upgrade_definer',:'delivery_definer_role',true),
 pg_catalog.set_config('app.delivery_upgrade_owner',:'expected_table_owner_role',true);

DO $preflight$
DECLARE owner_oid oid; delivery_definer oid; audit_oid oid; marker_oid oid; row record;
BEGIN
 SELECT oid INTO owner_oid FROM pg_catalog.pg_roles WHERE rolname=current_setting('app.delivery_upgrade_owner');
 SELECT oid INTO delivery_definer FROM pg_catalog.pg_roles WHERE rolname=current_setting('app.delivery_upgrade_definer');
 SELECT p.oid INTO audit_oid FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language language_row ON language_row.oid=p.prolang
  WHERE p.oid=pg_catalog.to_regprocedure('enrollment_execution.audit_execution_privileges(uuid)')
    AND p.proowner=owner_oid AND language_row.lanname='plpgsql' AND p.prosecdef AND p.provolatile='s'
    AND p.proparallel='u' AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp','row_security=on']
    AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
      pg_catalog.btrim(pg_catalog.regexp_replace(p.prosrc,'[[:space:]]+',' ','g')),'UTF8')),'hex')
      ='b25732a9b6d2e524f4263ff4826ece6625420ca522d28f3b0aeb9fe3f1df4f80';
 SELECT p.oid INTO marker_oid FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language language_row ON language_row.oid=p.prolang
  WHERE p.oid=pg_catalog.to_regprocedure('enrollment_execution.execution_store_profile()')
    AND p.proowner=owner_oid AND language_row.lanname='sql' AND NOT p.prosecdef AND p.provolatile='i'
    AND p.proparallel='s' AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
    AND pg_catalog.btrim(p.prosrc,E' \t\r\n')='SELECT 3::smallint';
 IF owner_oid IS NULL OR owner_oid<>CURRENT_USER::regrole::oid OR delivery_definer IS NULL
  OR delivery_definer=owner_oid OR audit_oid IS NULL OR marker_oid IS NULL
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_roles role WHERE role.oid=delivery_definer AND
      (role.rolcanlogin OR role.rolsuper OR role.rolbypassrls OR role.rolcreatedb OR role.rolcreaterole
        OR role.rolinherit OR role.rolreplication))
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members membership
      WHERE membership.member=delivery_definer OR membership.roleid=delivery_definer)
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_database database_row WHERE database_row.datdba=delivery_definer)
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_namespace namespace_row WHERE namespace_row.nspowner=delivery_definer)
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_class relation WHERE relation.relowner=delivery_definer)
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc function_row WHERE function_row.proowner=delivery_definer)
  OR EXISTS(SELECT 1 FROM enrollment_execution.role_reservations reservation
      WHERE reservation.role_name=current_setting('app.delivery_upgrade_definer')::name
         OR reservation.role_oid=delivery_definer)
  OR EXISTS(SELECT 1 FROM public."DirectoryDatabaseBindings" binding
      WHERE binding."Purpose" IN('EnrollmentGrantStatusRefresh','EnrollmentGrantDelivery'))
  OR EXISTS(SELECT 1 FROM enrollment_execution.role_reservations reservation
      WHERE reservation.capability='EnrollmentGrantDelivery'
         OR reservation.role_kind IN('DeliveryDefiner','StatusRuntime','DeliveryRuntime'))
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc function_row
      WHERE function_row.pronamespace='enrollment_execution'::regnamespace
        AND function_row.proname IN('delivery_worker_scope','audit_delivery_privileges','read_grant_status_receipt',
          'append_grant_status_observation','read_grant_delivery','acknowledge_grant_delivery','reject_delivery_update'))
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_policy policy_row WHERE policy_row.polname LIKE 'enrollment_delivery_%')
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_trigger trigger_row
      WHERE NOT trigger_row.tgisinternal AND trigger_row.tgname LIKE 'enrollment_delivery_%')
  OR pg_catalog.to_regclass('enrollment_execution.status_observations') IS NULL
  OR pg_catalog.to_regprocedure('enrollment_execution.record_status_observation(uuid,uuid,uuid,text,text,timestamptz,timestamptz,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea)') IS NULL
  OR pg_catalog.to_regprocedure('enrollment_execution.read_status_refresh_receipt(uuid,uuid)') IS NULL
  OR pg_catalog.to_regprocedure('enrollment_execution.lock_delivery_context(uuid,uuid,uuid,text)') IS NULL
  OR pg_catalog.to_regprocedure('enrollment_execution.get_sealed_delivery(uuid,uuid,uuid,text)') IS NULL
  OR pg_catalog.to_regprocedure('enrollment_execution.ack_sealed_delivery(uuid,uuid,uuid,text,bytea,bytea)') IS NULL THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Enrollment execution v4 upgrade preflight failed.';
 END IF;
 FOR row IN SELECT binding."EnvironmentId" environment_id FROM public."DirectoryDatabaseBindings" binding
     WHERE binding."Purpose"='EnrollmentGrantExecution'
 LOOP
   IF NOT EXISTS(SELECT 1 FROM enrollment_execution.audit_execution_privileges(row.environment_id) audit
       WHERE audit.is_valid AND audit.diagnostic_code='None' AND audit.profile_version=3) THEN
     RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Enrollment execution v3 source profile is invalid.';
   END IF;
 END LOOP;
 IF NOT FOUND THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Enrollment execution v3 source profile is empty.';
 END IF;
END
$preflight$;

\ir owner-mapping-guard-v1.sql

ALTER TABLE public."DirectoryDatabaseBindings" DROP CONSTRAINT directory_database_binding_purpose;
ALTER TABLE public."DirectoryDatabaseBindings" DROP CONSTRAINT directory_database_binding_shape;
ALTER TABLE public."DirectoryDatabaseBindings" ADD CONSTRAINT directory_database_binding_purpose
 CHECK("Purpose" IN('Api','Connector','EnrollmentGrantExecution','EnrollmentGrantStatusRefresh','EnrollmentGrantDelivery'));
ALTER TABLE public."DirectoryDatabaseBindings" ADD CONSTRAINT directory_database_binding_shape CHECK(
 ("Purpose"='Api' AND "ContractVersion"=1 AND "EnvironmentId" IS NULL AND "PrincipalId" IS NULL)
 OR ("Purpose"='Connector' AND "ContractVersion"=1 AND "EnvironmentId" IS NOT NULL AND "PrincipalId" IS NOT NULL)
 OR ("Purpose"='EnrollmentGrantExecution' AND "ContractVersion"=2 AND "EnvironmentId" IS NOT NULL
     AND "PrincipalId" IS NULL AND "EnvironmentId"<>'00000000-0000-0000-0000-000000000000'::uuid)
 OR ("Purpose" IN('EnrollmentGrantStatusRefresh','EnrollmentGrantDelivery') AND "ContractVersion"=1
     AND "EnvironmentId" IS NOT NULL AND "PrincipalId" IS NULL
     AND "EnvironmentId"<>'00000000-0000-0000-0000-000000000000'::uuid));
CREATE UNIQUE INDEX enrollment_grant_status_environment_login ON public."DirectoryDatabaseBindings"("EnvironmentId")
 WHERE "Purpose"='EnrollmentGrantStatusRefresh';
CREATE UNIQUE INDEX enrollment_grant_delivery_environment_login ON public."DirectoryDatabaseBindings"("EnvironmentId")
 WHERE "Purpose"='EnrollmentGrantDelivery';

ALTER TABLE enrollment_execution.role_reservations DROP CONSTRAINT role_reservations_capability_check;
ALTER TABLE enrollment_execution.role_reservations DROP CONSTRAINT role_reservations_role_kind_check;
ALTER TABLE enrollment_execution.role_reservations ADD CONSTRAINT role_reservations_capability_check
 CHECK(capability IN('EnrollmentGrantExecution','EnrollmentGrantDelivery'));
ALTER TABLE enrollment_execution.role_reservations ADD CONSTRAINT role_reservations_role_kind_check CHECK(
 (capability='EnrollmentGrantExecution' AND role_kind IN('Runtime','Definer','QueueDefiner'))
 OR (capability='EnrollmentGrantDelivery' AND role_kind IN('DeliveryDefiner','StatusRuntime','DeliveryRuntime')));
INSERT INTO enrollment_execution.role_reservations(role_name,role_oid,capability,role_kind,reservation_schema_version)
 SELECT :'delivery_definer_role'::name,oid,'EnrollmentGrantDelivery','DeliveryDefiner',1
 FROM pg_catalog.pg_roles WHERE rolname=:'delivery_definer_role';

DROP FUNCTION enrollment_execution.reject_worker_update() CASCADE;
DROP TRIGGER work_queue_outbox_consistent ON public."Outbox";
DO $drop_policies$ DECLARE row record; BEGIN
 FOR row IN SELECT namespace_row.nspname,relation.relname,policy_row.polname FROM pg_catalog.pg_policy policy_row
   JOIN pg_catalog.pg_class relation ON relation.oid=policy_row.polrelid
   JOIN pg_catalog.pg_namespace namespace_row ON namespace_row.oid=relation.relnamespace
   WHERE policy_row.polname LIKE 'enrollment_execution_worker_%' OR policy_row.polname LIKE 'enrollment_execution_queue_%'
 LOOP EXECUTE pg_catalog.format('DROP POLICY %I ON %I.%I',row.polname,row.nspname,row.relname); END LOOP;
END $drop_policies$;
DROP FUNCTION enrollment_execution.execution_store_profile();

\ir enrollment-execution-functions.sql
\ir enrollment-execution-queue.sql
\ir enrollment-delivery-journal.sql
\ir enrollment-execution-profile.sql
\ir enrollment-delivery-profile.sql

-- Trigger invocation does not require caller EXECUTE; these legacy guards are not callable APIs.
REVOKE ALL ON FUNCTION public.guard_role_identity(),public.guard_owner_mapping(),
 public.forbid_audit_mutation(),public.guard_operator_identity() FROM PUBLIC;

-- delivery_worker_scope remains table-owner SECURITY DEFINER, executable only by the delivery definer.
ALTER FUNCTION enrollment_execution.read_grant_status_receipt(uuid,uuid) OWNER TO :"delivery_definer_role";
ALTER FUNCTION enrollment_execution.append_grant_status_observation(uuid,uuid,uuid,text,text,timestamptz,timestamptz,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea) OWNER TO :"delivery_definer_role";
ALTER FUNCTION enrollment_execution.read_grant_delivery(uuid,uuid,uuid,text) OWNER TO :"delivery_definer_role";
ALTER FUNCTION enrollment_execution.acknowledge_grant_delivery(uuid,uuid,uuid,text,bytea,bytea) OWNER TO :"delivery_definer_role";

GRANT USAGE ON SCHEMA enrollment_execution TO :"delivery_definer_role";
GRANT EXECUTE ON FUNCTION enrollment_execution.audit_delivery_privileges(uuid),
 enrollment_execution.read_status_refresh_receipt(uuid,uuid),
 enrollment_execution.record_status_observation(uuid,uuid,uuid,text,text,timestamptz,timestamptz,uuid,uuid,uuid,timestamptz,timestamptz,timestamptz,smallint,timestamptz,bytea,bytea),
 enrollment_execution.lock_delivery_context(uuid,uuid,uuid,text),
 enrollment_execution.get_sealed_delivery(uuid,uuid,uuid,text),
 enrollment_execution.ack_sealed_delivery(uuid,uuid,uuid,text,bytea,bytea),
 enrollment_execution.has_computer_permission(uuid,uuid,uuid,uuid,text),
 enrollment_execution.scope_uuid(text) TO :"delivery_definer_role";
GRANT SELECT("Id","Version"),UPDATE("Name") ON public."Environments" TO :"delivery_definer_role";
GRANT SELECT("EnvironmentId","Status","Generation","CompletedAt"),UPDATE("ErrorCode") ON public."DirectorySync" TO :"delivery_definer_role";
GRANT SELECT("EnvironmentId","Id","Generation","Kind","Department","ParentOuId","OuAncestry"),UPDATE("Name")
 ON public."DirectoryObjects" TO :"delivery_definer_role";
GRANT SELECT("Id","OperatorId","Enabled"),UPDATE("DisplayName") ON public."Principals" TO :"delivery_definer_role";
GRANT SELECT("EnvironmentId","PrincipalId","Active"),UPDATE("Active") ON public."Memberships" TO :"delivery_definer_role";
GRANT SELECT("IdHash","PrincipalId","CreatedAt","LastSeenAt","ExpiresAt","StepUpAt","RevokedAt")
 ON public."Sessions" TO :"delivery_definer_role";
GRANT SELECT("EnvironmentId","Id","RequesterId","DirectoryObjectId","PlanHash","QueuedAt","AuthorizationNotAfter","RecipientKeyFingerprint","ServerDeviceId","MappingCreatedAt"),UPDATE("PlanHash")
 ON public."EnrollmentGrantOperations" TO :"delivery_definer_role";
GRANT SELECT ON public."Roles",public."RolePermissions",public."Assignments",public."Scopes",public."DeviceTagAssignments"
 TO :"delivery_definer_role";
GRANT SELECT ON enrollment_execution.issue_results,enrollment_execution.mint_permits TO :"delivery_definer_role";
GRANT SELECT ON enrollment_execution.execution_stops TO :"delivery_definer_role";
GRANT SELECT,DELETE ON enrollment_execution.sealed_envelopes TO :"delivery_definer_role";
GRANT SELECT,INSERT ON enrollment_execution.delivery_acks,enrollment_execution.status_observations TO :"delivery_definer_role";
GRANT EXECUTE ON FUNCTION public.has_environment_membership(uuid,uuid),public.directory_database_access(uuid,uuid) TO :"delivery_definer_role";
REVOKE CREATE ON SCHEMA public,enrollment_execution FROM :"delivery_definer_role";

CREATE FUNCTION enrollment_execution.execution_store_profile() RETURNS smallint
 LANGUAGE sql IMMUTABLE PARALLEL SAFE SECURITY INVOKER SET search_path=pg_catalog,pg_temp
 AS 'SELECT 4::smallint';
REVOKE ALL ON FUNCTION enrollment_execution.execution_store_profile() FROM PUBLIC;
ALTER FUNCTION enrollment_execution.execution_store_profile() OWNER TO :"expected_table_owner_role";

DO $postflight$ DECLARE row record; BEGIN
 FOR row IN SELECT binding."EnvironmentId" environment_id FROM public."DirectoryDatabaseBindings" binding
   WHERE binding."Purpose"='EnrollmentGrantExecution'
 LOOP
  IF NOT EXISTS(SELECT 1 FROM enrollment_execution.audit_execution_privileges(row.environment_id) audit
      WHERE audit.is_valid AND audit.diagnostic_code='None' AND audit.profile_version=4) THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='Enrollment execution v4 postflight failed.';
  END IF;
 END LOOP;
END $postflight$;
COMMIT;
