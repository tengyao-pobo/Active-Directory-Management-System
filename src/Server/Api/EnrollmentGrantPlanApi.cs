using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using ItManagement.AgentEnrollment.Crypto;
using ItManagement.AgentEnrollmentTargets;
using ItManagement.Core;
using ItManagement.Persistence;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using Npgsql;

namespace ItManagement.Api;

public sealed record EnrollmentGrantPlanDto(
    Guid Id,
    Guid EnvironmentId,
    Guid DirectoryObjectId,
    Guid RequesterId,
    Guid RequestId,
    string RecipientKeyFingerprint,
    string PlanHash,
    long PolicyVersion,
    Guid DirectoryGeneration,
    DateTimeOffset ExpiresAt,
    DateTimeOffset QueriedAt,
    string State,
    string Reason,
    bool CanApprove,
    bool CanRequest);

public static partial class EnrollmentGrantPlanApi
{
    private static readonly JsonSerializerOptions StrictJson = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    public static void MapEnrollmentGrantPlans(this WebApplication app)
    {
        app.MapPost("/api/v1/environments/{environmentId:guid}/devices/{directoryObjectId:guid}/enrollment-grant-plans", Create);
        app.MapGet("/api/v1/environments/{environmentId:guid}/enrollment-grant-plans/{planId:guid}", Read);
        app.MapPost("/api/v1/environments/{environmentId:guid}/enrollment-grant-plans/{planId:guid}/approval", Approve);
        app.MapPost("/api/v1/environments/{environmentId:guid}/enrollment-grant-plans/{planId:guid}/execution", QueueExecution);
        app.MapGet("/api/v1/environments/{environmentId:guid}/enrollment-grant-operations/{operationId:guid}", ReadExecution);
    }

    internal static bool IsDedicatedAction(string action) =>
        string.Equals(action, EnrollmentGrantPlanContract.Action, StringComparison.Ordinal);

    internal static async Task<bool> LockHelperIsValidAsync(ConsoleDbContext db, CancellationToken ct)
    {
        var body = await db.Database.SqlQueryRaw<string>("""
            SELECT p.prosrc AS "Value" FROM pg_proc p
            WHERE p.oid='public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[])'::regprocedure
            """).SingleOrDefaultAsync(ct);
        var rejectBody = await db.Database.SqlQueryRaw<string>("""
            SELECT p.prosrc AS "Value" FROM pg_proc p
            WHERE p.oid='public.reject_enrollment_grant_reservation_mutation()'::regprocedure
            """).SingleOrDefaultAsync(ct);
        if (body is null || rejectBody is null ||
            !string.Equals(NormalizeSqlBody(body), NormalizeSqlBody(ExpectedFunctionBody("CREATE FUNCTION public.lock_enrollment_grant_plan_context")), StringComparison.Ordinal) ||
            !string.Equals(NormalizeSqlBody(rejectBody), NormalizeSqlBody(ExpectedFunctionBody("CREATE FUNCTION public.reject_enrollment_grant_reservation_mutation")), StringComparison.Ordinal)) return false;
        var audit = await db.Database.SqlQueryRaw<EnrollmentGrantPlanAuditRow>("""
            WITH target AS (
                SELECT p.*,r.oid AS owner_oid,r.rolname AS owner_name,r.rolcanlogin,r.rolsuper,r.rolbypassrls,
                    r.rolcreatedb,r.rolcreaterole,r.rolinherit,r.rolreplication,l.lanname
                FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner JOIN pg_language l ON l.oid=p.prolang
                WHERE p.oid='public.lock_enrollment_grant_plan_context(uuid,uuid,uuid[])'::regprocedure
            ), expected_tables(schema_name,table_name,privilege_type,is_grantable) AS (VALUES
                ('public','DirectoryDatabaseBindings','SELECT',false),('public','Environments','SELECT',false),('public','Environments','UPDATE',false),
                ('public','DirectorySync','SELECT',false),('public','DirectorySync','UPDATE',false),('public','DirectoryObjects','SELECT',false),('public','DirectoryObjects','UPDATE',false),
                ('public','Principals','SELECT',false),('public','Principals','UPDATE',false),('public','Memberships','SELECT',false),('public','Memberships','UPDATE',false)
            ), actual_tables AS (
                SELECT n.nspname::text AS schema_name,c.relname::text AS table_name,a.privilege_type::text,a.is_grantable
                FROM target t JOIN pg_class c ON true JOIN pg_namespace n ON n.oid=c.relnamespace
                CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
                WHERE c.relkind IN ('r','p','v','m','f') AND a.grantee=t.owner_oid
            ), expected_functions(function_oid,is_grantable) AS (VALUES
                ('public.has_environment_membership(uuid,uuid)'::regprocedure::oid,false),('public.directory_database_access(uuid,uuid)'::regprocedure::oid,false)
            ), actual_functions AS (
                SELECT p.oid AS function_oid,a.is_grantable
                FROM target t JOIN pg_proc p ON true CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
                WHERE a.grantee=t.owner_oid AND a.privilege_type='EXECUTE'
            ), actual_lock_acl AS (
                SELECT a.grantee,a.is_grantable FROM target t
                CROSS JOIN LATERAL aclexplode(coalesce(t.proacl,acldefault('f',t.proowner))) a
                WHERE a.privilege_type='EXECUTE'
            ), expected_lock_acl AS (
                SELECT r.oid AS grantee,false AS is_grantable FROM pg_roles r WHERE r.rolname=SESSION_USER
            ), reservation AS (
                SELECT c.oid,c.relowner,c.relrowsecurity,c.relforcerowsecurity
                FROM pg_class c WHERE c.oid='public."EnrollmentGrantRecipientReservations"'::regclass AND c.relkind='r'
            ), expected_columns(column_name,type_name,is_not_null) AS (VALUES
                ('Fingerprint','bytea',true),('EnvironmentId','uuid',true),('PlanId','uuid',true),('RequesterId','uuid',true),
                ('RequestId','uuid',true),('RequestDigest','bytea',true),('CreatedAt','timestamp with time zone',true)
            ), actual_columns AS (
                SELECT a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull
                FROM reservation r JOIN pg_attribute a ON a.attrelid=r.oid
                WHERE a.attnum>0 AND NOT a.attisdropped
            ), expected_reservation_acl(privilege_type,is_grantable) AS (VALUES ('SELECT',false),('INSERT',false)),
            actual_reservation_acl AS (
                SELECT a.privilege_type::text,a.is_grantable
                FROM reservation r CROSS JOIN LATERAL aclexplode(coalesce((SELECT relacl FROM pg_class WHERE oid=r.oid),acldefault('r',r.relowner))) a
                JOIN pg_roles role ON role.oid=a.grantee
                WHERE a.grantee<>r.relowner AND role.rolname=SESSION_USER
            ), unexpected_reservation_acl AS (
                SELECT 1 FROM reservation r CROSS JOIN LATERAL aclexplode(coalesce((SELECT relacl FROM pg_class WHERE oid=r.oid),acldefault('r',r.relowner))) a
                LEFT JOIN pg_roles role ON role.oid=a.grantee
                WHERE a.grantee<>r.relowner AND (a.grantee=0 OR role.rolname IS DISTINCT FROM SESSION_USER)
            ), execution_marker AS (
                SELECT p.*,l.lanname FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang JOIN pg_namespace n ON n.oid=p.pronamespace
                WHERE n.nspname='enrollment_execution' AND p.proname='execution_store_profile' AND p.pronargs=0
            ), execution_audit AS (
                SELECT p.*,l.lanname FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang JOIN pg_namespace n ON n.oid=p.pronamespace
                WHERE n.nspname='enrollment_execution' AND p.proname='audit_execution_privileges' AND p.proargtypes='2950'::oidvector
            ), execution_definer AS (
                SELECT r.* FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner
                WHERE n.nspname='enrollment_execution' AND p.proname='read_execution_record' AND p.proargtypes='2950 2950'::oidvector
            ), execution_profile AS (
                SELECT COALESCE(
                  (SELECT count(*)=1 AND bool_and(lanname='sql' AND NOT prosecdef AND provolatile='i' AND proparallel='s'
                    AND proowner=(SELECT relowner FROM reservation) AND proconfig=ARRAY['search_path=pg_catalog, pg_temp']
                    AND btrim(prosrc,E' \t\r\n') IN('SELECT 2::smallint','SELECT 3::smallint')) FROM execution_marker)
                  AND (SELECT count(*)=1 AND bool_and(lanname='plpgsql' AND prosecdef AND provolatile='s' AND proparallel='u'
                    AND proowner=(SELECT relowner FROM reservation) AND proconfig=ARRAY['search_path=pg_catalog, pg_temp','row_security=on']
                    AND encode(sha256(convert_to(btrim(regexp_replace(prosrc,'[[:space:]]+',' ','g')),'UTF8')),'hex')
                      =CASE (SELECT btrim(prosrc,E' \t\r\n') FROM execution_marker)
                         WHEN 'SELECT 2::smallint' THEN '8ed83a1a4736e9caab7c0a9c32ef8b2e53b48dbdcf184824a8436d3fc33d3da3'
                         WHEN 'SELECT 3::smallint' THEN 'ec0ae2639db2b390471dd63fba05c7851a34112068e425d2d60066770fa16650'
                         ELSE '' END) FROM execution_audit)
                  AND (SELECT count(*)=1 AND bool_and(NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreatedb
                    AND NOT rolcreaterole AND NOT rolinherit AND NOT rolreplication) FROM execution_definer),false) installed
            ), reject_function AS (
                SELECT p.*,l.lanname FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang
                WHERE p.oid='public.reject_enrollment_grant_reservation_mutation()'::regprocedure
            ), runtime AS (
                SELECT * FROM pg_roles WHERE rolname=SESSION_USER
            ), expected_schema_acl(schema_name,privilege_type,is_grantable) AS (VALUES ('public','USAGE',false)),
            actual_schema_acl AS (
                SELECT n.nspname::text,acl.privilege_type::text,acl.is_grantable
                FROM target t JOIN pg_namespace n ON true CROSS JOIN LATERAL aclexplode(n.nspacl) acl
                WHERE acl.grantee=t.owner_oid
            )
            SELECT valid AS "IsValid", CASE WHEN valid THEN 'None' ELSE 'PrivilegeAuditFailed' END AS "DiagnosticCode",
                1::smallint AS "ProfileVersion" FROM (SELECT ((SELECT count(*) FROM target)=1 AND
                (SELECT lanname='plpgsql' AND prosecdef AND provolatile='v' AND proparallel='u' AND prorettype='void'::regtype AND
                    proargtypes='2950 2950 2951'::oidvector AND
                    proargnames=ARRAY['p_environment_id','p_directory_object_id','p_principal_ids'] AND proallargtypes IS NULL AND proargmodes IS NULL AND
                    proconfig=ARRAY['search_path=pg_catalog, pg_temp'] AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND
                    NOT rolcreatedb AND NOT rolcreaterole AND NOT rolinherit AND NOT rolreplication FROM target) AND
                NOT EXISTS (SELECT 1 FROM target t JOIN pg_auth_members m ON m.roleid=t.owner_oid OR m.member=t.owner_oid) AND
                NOT EXISTS (SELECT 1 FROM target t JOIN pg_database d ON d.datdba=t.owner_oid) AND
                NOT EXISTS (SELECT 1 FROM target t JOIN pg_namespace n ON n.nspowner=t.owner_oid) AND
                NOT EXISTS (SELECT 1 FROM target t JOIN pg_class c ON c.relowner=t.owner_oid) AND
                NOT EXISTS (SELECT 1 FROM target t JOIN pg_proc p ON p.proowner=t.owner_oid WHERE p.oid<>t.oid) AND
                NOT EXISTS (SELECT * FROM expected_tables EXCEPT SELECT * FROM actual_tables) AND
                NOT EXISTS (SELECT * FROM actual_tables EXCEPT SELECT * FROM expected_tables) AND
                NOT EXISTS (SELECT * FROM expected_functions EXCEPT SELECT * FROM actual_functions) AND
                NOT EXISTS (SELECT * FROM actual_functions EXCEPT SELECT * FROM expected_functions) AND
                NOT EXISTS (SELECT * FROM expected_schema_acl EXCEPT SELECT * FROM actual_schema_acl) AND
                NOT EXISTS (SELECT * FROM actual_schema_acl EXCEPT SELECT * FROM expected_schema_acl) AND
                NOT EXISTS (SELECT 1 FROM target t JOIN pg_attribute a ON a.attrelid<>0 CROSS JOIN LATERAL aclexplode(a.attacl) acl WHERE acl.grantee=t.owner_oid) AND
                NOT EXISTS (SELECT 1 FROM target t JOIN pg_class c ON true WHERE CASE WHEN c.relkind='S' THEN has_sequence_privilege(t.owner_name,c.oid,'USAGE,SELECT,UPDATE') ELSE false END) AND
                NOT EXISTS (SELECT * FROM expected_lock_acl EXCEPT SELECT * FROM actual_lock_acl) AND
                NOT EXISTS (SELECT * FROM actual_lock_acl EXCEPT SELECT * FROM expected_lock_acl) AND
                NOT has_table_privilege(SESSION_USER,'public."DirectorySync"','INSERT,UPDATE,DELETE,TRUNCATE') AND
                NOT has_table_privilege(SESSION_USER,'public."DirectoryObjects"','INSERT,UPDATE,DELETE,TRUNCATE') AND
                NOT has_any_column_privilege(SESSION_USER,'public."DirectorySync"','INSERT,UPDATE') AND
                NOT has_any_column_privilege(SESSION_USER,'public."DirectoryObjects"','INSERT,UPDATE') AND
                (SELECT count(*)=1 AND bool_and(relrowsecurity AND relforcerowsecurity) FROM reservation) AND
                NOT EXISTS (SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns) AND
                NOT EXISTS (SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns) AND
                NOT EXISTS (SELECT * FROM expected_reservation_acl EXCEPT SELECT * FROM actual_reservation_acl) AND
                NOT EXISTS (SELECT * FROM actual_reservation_acl EXCEPT SELECT * FROM expected_reservation_acl) AND
                NOT EXISTS (SELECT 1 FROM unexpected_reservation_acl) AND
                (SELECT CASE WHEN profile.installed THEN
                  (SELECT count(*)=7 AND bool_and(acl.grantee=(SELECT oid FROM execution_definer)
                    AND acl.privilege_type='SELECT' AND NOT acl.is_grantable
                    AND a.attname IN('Fingerprint','EnvironmentId','PlanId','RequesterId','RequestId','RequestDigest','CreatedAt'))
                   FROM reservation r JOIN pg_attribute a ON a.attrelid=r.oid CROSS JOIN LATERAL aclexplode(a.attacl) acl)
                  ELSE NOT EXISTS(SELECT 1 FROM reservation r JOIN pg_attribute a ON a.attrelid=r.oid
                    CROSS JOIN LATERAL aclexplode(a.attacl) acl) END FROM execution_profile profile) AND
                (SELECT count(*)=1 FROM pg_constraint c JOIN reservation r ON r.oid=c.conrelid
                    WHERE c.contype='p' AND c.conkey=ARRAY[(SELECT attnum FROM pg_attribute WHERE attrelid=r.oid AND attname='Fingerprint')]::smallint[]) AND
                (SELECT count(*)=1 FROM pg_index i JOIN reservation r ON r.oid=i.indrelid
                    WHERE i.indisunique AND i.indisvalid AND i.indisready AND NOT i.indisprimary AND i.indpred IS NULL AND
                    ARRAY(SELECT a.attname::text FROM unnest(i.indkey) WITH ORDINALITY k(attnum,ord) JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum ORDER BY k.ord)
                    =ARRAY['EnvironmentId','PlanId']) AND
                (SELECT count(*)=1 FROM pg_index i JOIN reservation r ON r.oid=i.indrelid
                    WHERE i.indisunique AND i.indisvalid AND i.indisready AND NOT i.indisprimary AND i.indpred IS NULL AND
                    ARRAY(SELECT a.attname::text FROM unnest(i.indkey) WITH ORDINALITY k(attnum,ord) JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum ORDER BY k.ord)
                    =ARRAY['EnvironmentId','RequesterId','RequestId']) AND
                (SELECT count(*)=3 FROM pg_index i JOIN reservation r ON r.oid=i.indrelid WHERE i.indisunique AND NOT i.indisprimary) AND
                (SELECT count(*)=1 FROM pg_index i JOIN reservation r ON r.oid=i.indrelid
                    WHERE i.indisunique AND i.indisvalid AND i.indisready AND NOT i.indisprimary AND i.indpred IS NULL AND i.indexprs IS NULL AND i.indnatts=5 AND
                    ARRAY(SELECT a.attname::text FROM unnest(i.indkey) WITH ORDINALITY k(attnum,ord) JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum ORDER BY k.ord)
                    =ARRAY['Fingerprint','EnvironmentId','PlanId','RequesterId','RequestId']) AND
                (SELECT count(*)=1 FROM pg_constraint c JOIN reservation r ON r.oid=c.conrelid WHERE c.contype='f' AND c.confrelid='public."Plans"'::regclass AND c.confdeltype='r' AND
                    pg_get_constraintdef(c.oid,true)='FOREIGN KEY ("EnvironmentId", "PlanId") REFERENCES "Plans"("EnvironmentId", "Id") ON DELETE RESTRICT') AND
                (SELECT count(*)=3 FROM pg_constraint c JOIN reservation r ON r.oid=c.conrelid WHERE c.contype='c' AND c.convalidated AND
                    (c.conname,pg_get_constraintdef(c.oid,true)) IN (
                        ('enrollment_grant_recipient_fingerprint_length','CHECK (octet_length("Fingerprint") = 32)'),
                        ('enrollment_grant_request_digest_length','CHECK (octet_length("RequestDigest") = 32)'),
                        ('enrollment_grant_reservation_ids_nonempty','CHECK ("EnvironmentId" <> ''00000000-0000-0000-0000-000000000000''::uuid AND "PlanId" <> ''00000000-0000-0000-0000-000000000000''::uuid AND "RequesterId" <> ''00000000-0000-0000-0000-000000000000''::uuid AND "RequestId" <> ''00000000-0000-0000-0000-000000000000''::uuid)'))) AND
                EXISTS (SELECT 1 FROM pg_constraint c WHERE c.conrelid='public."Plans"'::regclass AND c.conname='enrollment_grant_plan_never_executed' AND c.contype='c' AND c.convalidated AND
                    pg_get_constraintdef(c.oid,true)='CHECK ("Action" <> ''agent-enrollment.initial-grant.v1''::text OR "State" <> 2)') AND
                (SELECT count(*)=CASE WHEN (SELECT installed FROM execution_profile) THEN 3 ELSE 1 END
                    FROM pg_policy p JOIN reservation r ON r.oid=p.polrelid) AND
                (SELECT count(*)=1 FROM pg_policy p JOIN reservation r ON r.oid=p.polrelid WHERE p.polname='environment_enrollment_grant_recipient_reservations' AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid] AND
                    pg_get_expr(p.polqual,p.polrelid)=pg_get_expr(p.polwithcheck,p.polrelid) AND
                    pg_get_expr(p.polqual,p.polrelid)='((("EnvironmentId")::text = current_setting(''app.environment_id''::text, true)) AND has_environment_membership("EnvironmentId", (NULLIF(current_setting(''app.principal_id''::text, true), ''''::text))::uuid))') AND
                (SELECT NOT profile.installed OR (SELECT count(*)=2 AND bool_and(p.polcmd='r' AND p.polroles=ARRAY[(SELECT oid FROM execution_definer)]
                    AND ((p.polname='enrollment_execution_worker_reservations_allow' AND p.polpermissive)
                      OR (p.polname='enrollment_execution_worker_reservations_limit' AND NOT p.polpermissive))
                    AND p.polwithcheck IS NULL
                    AND md5(COALESCE(pg_get_expr(p.polqual,p.polrelid),'')||'|'||COALESCE(pg_get_expr(p.polwithcheck,p.polrelid),''))
                      ='158b72978f11ad4651c98e8dbe14e0c0')
                  FROM pg_policy p JOIN reservation r ON r.oid=p.polrelid
                  WHERE p.polname IN('enrollment_execution_worker_reservations_allow','enrollment_execution_worker_reservations_limit'))
                 FROM execution_profile profile) AND
                (SELECT count(*)=1 FROM pg_trigger tg JOIN reservation r ON r.oid=tg.tgrelid WHERE NOT tg.tgisinternal) AND
                (SELECT count(*)=1 FROM pg_trigger tg JOIN reservation r ON r.oid=tg.tgrelid WHERE NOT tg.tgisinternal AND tg.tgenabled='O' AND tg.tgname='enrollment_grant_recipient_reservations_immutable' AND
                    tg.tgfoid='public.reject_enrollment_grant_reservation_mutation()'::regprocedure AND (tg.tgtype & 1)=1 AND (tg.tgtype & 2)=2 AND (tg.tgtype & 8)=8 AND (tg.tgtype & 16)=16 AND (tg.tgtype & 4)=0) AND
                (SELECT count(*)=1 AND bool_and(lanname='plpgsql' AND NOT prosecdef AND provolatile='v' AND proparallel='u' AND prorettype='trigger'::regtype AND
                    proargtypes=''::oidvector AND proargnames IS NULL AND proallargtypes IS NULL AND proargmodes IS NULL AND
                    proconfig=ARRAY['search_path=pg_catalog, public, pg_temp'] AND proowner=(SELECT relowner FROM reservation)) FROM reject_function) AND
                (SELECT count(*)=1 FROM reject_function rf CROSS JOIN LATERAL aclexplode(coalesce(rf.proacl,acldefault('f',rf.proowner))) acl
                    WHERE acl.grantee=rf.proowner AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable) AND
                (SELECT count(*)=1 FROM reject_function rf CROSS JOIN LATERAL aclexplode(coalesce(rf.proacl,acldefault('f',rf.proowner))) acl WHERE acl.privilege_type='EXECUTE') AND
                has_schema_privilege((SELECT owner_name FROM target),'public','USAGE') AND NOT has_schema_privilege((SELECT owner_name FROM target),'public','CREATE') AND
                NOT has_database_privilege((SELECT owner_name FROM target),current_database(),'CREATE') AND
                NOT has_database_privilege(SESSION_USER,current_database(),'CREATE') AND NOT has_schema_privilege(SESSION_USER,'public','CREATE') AND
                (SELECT count(*)=1 AND bool_and(rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolinherit AND NOT rolreplication) FROM runtime) AND
                NOT EXISTS (SELECT 1 FROM runtime r JOIN pg_auth_members m ON m.roleid=r.oid OR m.member=r.oid) AND
                NOT EXISTS (SELECT 1 FROM runtime r JOIN pg_database d ON d.datdba=r.oid) AND
                NOT EXISTS (SELECT 1 FROM runtime r JOIN pg_namespace n ON n.nspowner=r.oid) AND
                NOT EXISTS (SELECT 1 FROM runtime r JOIN pg_class c ON c.relowner=r.oid) AND
                NOT EXISTS (SELECT 1 FROM runtime r JOIN pg_proc p ON p.proowner=r.oid) AND
                NOT EXISTS (SELECT 1 FROM runtime r JOIN pg_namespace n ON n.nspname<>'public' CROSS JOIN LATERAL aclexplode(n.nspacl) acl WHERE acl.grantee=r.oid) AND
                NOT EXISTS (SELECT 1 FROM runtime r JOIN pg_class c ON true JOIN pg_namespace n ON n.oid=c.relnamespace AND n.nspname<>'public'
                    CROSS JOIN LATERAL aclexplode(c.relacl) acl WHERE acl.grantee=r.oid) AND
                NOT EXISTS (SELECT 1 FROM runtime r JOIN pg_attribute a ON a.attrelid<>0 JOIN pg_class c ON c.oid=a.attrelid
                    JOIN pg_namespace n ON n.oid=c.relnamespace AND n.nspname<>'public' CROSS JOIN LATERAL aclexplode(a.attacl) acl WHERE acl.grantee=r.oid) AND
                NOT EXISTS (SELECT 1 FROM runtime r JOIN pg_proc p ON true JOIN pg_namespace n ON n.oid=p.pronamespace AND n.nspname<>'public'
                    CROSS JOIN LATERAL aclexplode(p.proacl) acl WHERE acl.grantee=r.oid)) AS valid) audit
            """).SingleAsync(ct);
        return audit.IsValid && audit.DiagnosticCode == "None" && audit.ProfileVersion == 1;
    }

    private static string ExpectedFunctionBody(string declaration)
    {
        var sql = new global::Persistence.Migrations.EnrollmentGrantPlans().UpOperations.OfType<SqlOperation>()
            .Select(x => x.Sql).Single(x => x.Contains("CREATE FUNCTION public.lock_enrollment_grant_plan_context", StringComparison.Ordinal));
        var function = sql.IndexOf(declaration, StringComparison.Ordinal);
        var start = sql.IndexOf("AS $function$", function, StringComparison.Ordinal) + "AS $function$".Length;
        var end = sql.IndexOf("$function$;", start, StringComparison.Ordinal);
        return sql[start..end].Trim();
    }

    private static string NormalizeSqlBody(string value) => value.Replace("\r\n", "\n", StringComparison.Ordinal).Trim();

    private static async Task<IResult> Create(
        Guid environmentId,
        Guid directoryObjectId,
        JsonElement body,
        HttpContext http,
        ConsoleDbContext db,
        IEnrollmentTargetReader reader,
        ChangePlanService plans,
        TimeProvider time,
        ConsoleOptions config,
        CancellationToken ct)
    {
        if (!TryReadRequest(body, out var input) || environmentId == Guid.Empty || directoryObjectId == Guid.Empty)
            return InvalidRequest();
        if (!AuthEndpoints.FreshStepUp(http, time, config)) return Results.Problem(statusCode: 403, title: "StepUpRequired");

        EnrollmentGrantRecipientKey recipient;
        try { recipient = EnrollmentGrantRecipientKey.Validate(input.SubjectPublicKeyInfo); }
        catch (SealedEnrollmentGrantException) { return InvalidRequest(); }

        var canonicalSpki = WebEncoders.Base64UrlEncode(recipient.GetSubjectPublicKeyInfo());
        var fingerprint = recipient.GetFingerprintSha256();
        var fingerprintText = WebEncoders.Base64UrlEncode(fingerprint);
        var actor = AuthEndpoints.Actor(http);
        var now = Canonical(time.GetUtcNow());

        await using (var first = await db.BeginEnvironment(environmentId, actor, ct))
        {
            var current = await ReadCurrentTarget(db, environmentId, actor, directoryObjectId, now, ct);
            if (current is null) return Results.NotFound();
            if (!current.Value.DirectoryAvailable) return DirectoryUnavailable();
            if (current.Value.EnvironmentVersion != input.ExpectedEnvironmentVersion || current.Value.Generation != input.ExpectedDirectoryGeneration)
                return Results.Problem(statusCode: 412, title: "StaleVersion");
        }
        db.ChangeTracker.Clear();

        for (var attempt = 0; ; attempt++)
        {
            db.ChangeTracker.Clear();
            var resolved = await reader.ReadAsync(environmentId, directoryObjectId, ct);
            var attemptNow = Canonical(time.GetUtcNow());
            if (!AuthEndpoints.FreshStepUp(http, time, config)) return Results.Problem(statusCode: 403, title: "StepUpRequired");
            if (!ValidResolved(resolved, environmentId, directoryObjectId, attemptNow)) return EnrollmentTargetUnavailable();
            try
            {
                return await CreateAttempt(environmentId, directoryObjectId, input, actor, attemptNow, canonicalSpki, fingerprint,
                    fingerprintText, resolved, http, db, plans, time, config, ct);
            }
            catch (Exception error) when (attempt == 0 && IsSerialization(error)) { }
            catch (Exception error) when (IsSerialization(error)) { return Results.Problem(statusCode: 409, title: "ConcurrentChange"); }
            catch (PostgresException error) when (error.SqlState == "42501") { return Results.NotFound(); }
        }
    }

    private static async Task<IResult> CreateAttempt(Guid environmentId, Guid directoryObjectId, ProposalInput input,
        Guid actor, DateTimeOffset now, string canonicalSpki, byte[] fingerprint, string fingerprintText,
        EnrollmentTargetResult resolved, HttpContext http, ConsoleDbContext db, ChangePlanService plans, TimeProvider time,
        ConsoleOptions config, CancellationToken ct)
    {
        await using var tx = await db.BeginEnvironment(environmentId, actor, ct);
        await LockPublicContext(db, environmentId, directoryObjectId, [actor], ct);
        var requestLockKey = $"EnrollmentGrantPlanRequest.v1|{environmentId:D}|{actor:D}|{input.RequestId:D}";
        await db.Database.ExecuteSqlInterpolatedAsync($"SELECT pg_advisory_xact_lock(hashtextextended({requestLockKey}, 709763624))", ct);
        now = Canonical(time.GetUtcNow());
        if (!AuthEndpoints.FreshStepUp(http, time, config)) return Results.Problem(statusCode: 403, title: "StepUpRequired");
        if (!ValidResolved(resolved, environmentId, directoryObjectId, now)) return EnrollmentTargetUnavailable();
        var revalidated = await ReadCurrentTarget(db, environmentId, actor, directoryObjectId, now, ct);
        if (revalidated is null) return Results.NotFound();
        if (!revalidated.Value.DirectoryAvailable) return DirectoryUnavailable();
        if (revalidated.Value.EnvironmentVersion != input.ExpectedEnvironmentVersion || revalidated.Value.Generation != input.ExpectedDirectoryGeneration)
            return Results.Problem(statusCode: 409, title: "AuthorizationSnapshotChanged");

        var digest = ComputeRequestDigest(environmentId, actor, input.RequestId, directoryObjectId,
            resolved.DeviceId!.Value, resolved.MappingCreatedAt!.Value, input.ExpectedEnvironmentVersion,
            input.ExpectedDirectoryGeneration, canonicalSpki, input.Reason);
        var existingReservation = await db.EnrollmentGrantRecipientReservations.AsNoTracking()
            .SingleOrDefaultAsync(x => x.EnvironmentId == environmentId && x.RequesterId == actor && x.RequestId == input.RequestId, ct);
        if (existingReservation is not null)
        {
            if (!FixedEquals(existingReservation.RequestDigest, digest)) return RecipientUnavailable();
            var existing = await db.Plans.Include(x => x.Items).SingleOrDefaultAsync(x =>
                x.EnvironmentId == environmentId && x.Id == existingReservation.PlanId, ct);
            if (existing is null || !TryValidateStored(existing, existingReservation, out var existingPayload) ||
                !FixedEquals(existing.PlanHash, plans.ComputeHash(existing)) ||
                existing.ExpiresAt != existingReservation.CreatedAt.AddSeconds(EnrollmentGrantPlanContract.GrantTtlSeconds)) return PlanUnavailable();
            await tx.CommitAsync(ct);
            return Results.Ok(ToDto(existing, existingPayload, now, canApprove: false, canRequest: true));
        }

        var planId = Guid.NewGuid();
        var payload = new EnrollmentGrantPlanPayload(
            EnrollmentGrantPlanContract.SchemaVersion,
            EnrollmentGrantPlanContract.Action,
            environmentId,
            directoryObjectId,
            resolved.DeviceId.Value,
            resolved.MappingCreatedAt.Value,
            input.ExpectedDirectoryGeneration,
            input.ExpectedEnvironmentVersion,
            canonicalSpki,
            fingerprintText,
            input.RequestId,
            input.Reason,
            actor,
            Guid.NewGuid(),
            EnrollmentGrantPlanContract.GrantTtlSeconds);
        var plan = plans.Create(environmentId, planId, actor, EnrollmentGrantPlanContract.Action,
            JsonSerializer.Serialize(payload, StrictJson), input.ExpectedEnvironmentVersion, now.AddMinutes(10),
            [new ChangePlanItem { Id = Guid.NewGuid(), TargetId = environmentId.ToString(), ExpectedVersion = input.ExpectedEnvironmentVersion }], input.Reason);
        db.Plans.Add(plan);
        db.Audit.Add(Audit(http, now, environmentId, actor, "EnrollmentGrantPlan.Created", plan.Id, "PendingApproval"));
        await db.SaveChangesAsync(ct);
        var inserted = await db.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO public."EnrollmentGrantRecipientReservations"
                ("Fingerprint","EnvironmentId","PlanId","RequesterId","RequestId","RequestDigest","CreatedAt")
            VALUES ({fingerprint},{environmentId},{plan.Id},{actor},{input.RequestId},{digest},{now})
            ON CONFLICT DO NOTHING
            """, ct);
        if (inserted != 1) return RecipientUnavailable();
        await tx.CommitAsync(ct);
        return Results.Created($"/api/v1/environments/{environmentId}/enrollment-grant-plans/{plan.Id}",
            ToDto(plan, payload, now, canApprove: false, canRequest: true));
    }

    private static async Task<IResult> Read(
        Guid environmentId,
        Guid planId,
        HttpContext http,
        ConsoleDbContext db,
        IEnrollmentTargetReader reader,
        ChangePlanService plans,
        TimeProvider time,
        CancellationToken ct)
    {
        var actor = AuthEndpoints.Actor(http);
        var now = Canonical(time.GetUtcNow());
        ChangePlan plan;
        EnrollmentGrantRecipientReservation reservation;
        EnrollmentGrantPlanPayload payload;
        await using (var first = await db.BeginEnvironment(environmentId, actor, ct))
        {
            plan = await db.Plans.AsNoTracking().Include(x => x.Items).SingleOrDefaultAsync(x => x.EnvironmentId == environmentId && x.Id == planId, ct)
                ?? null!;
            if (plan is null || !IsDedicatedAction(plan.Action)) return Results.NotFound();
            reservation = await db.EnrollmentGrantRecipientReservations.AsNoTracking().SingleOrDefaultAsync(x => x.EnvironmentId == environmentId && x.PlanId == planId, ct)
                ?? null!;
            if (reservation is null || !TryValidateStored(plan, reservation, out payload)) return PlanUnavailable();
            if (plan.State == ChangePlanState.Queued)
                return await ReadQueuedPlan(db, plan, payload, actor, now, plans, ct);
            var access = await ReadAccess(db, environmentId, actor, payload, now, ct);
            if (!access.RequesterCurrent || !access.ActorCanRead) return Results.NotFound();
            if (!IsCurrent(plan, payload, access, now, plans)) return PlanUnavailable();
        }
        db.ChangeTracker.Clear();

        var resolved = await reader.ReadAsync(environmentId, payload.DirectoryObjectId, ct);
        now = Canonical(time.GetUtcNow());

        await using var second = await db.BeginEnvironment(environmentId, actor, ct);
        plan = await db.Plans.AsNoTracking().Include(x => x.Items).SingleOrDefaultAsync(x => x.EnvironmentId == environmentId && x.Id == planId, ct) ?? null!;
        reservation = await db.EnrollmentGrantRecipientReservations.AsNoTracking().SingleOrDefaultAsync(x => x.EnvironmentId == environmentId && x.PlanId == planId, ct) ?? null!;
        if (plan is null || reservation is null || !IsDedicatedAction(plan.Action) || !TryValidateStored(plan, reservation, out payload)) return PlanUnavailable();
        if (plan.State == ChangePlanState.Queued)
            return await ReadQueuedPlan(db, plan, payload, actor, now, plans, ct);
        if (!MatchesResolved(resolved, payload, now)) return EnrollmentTargetUnavailable();
        var current = await ReadAccess(db, environmentId, actor, payload, now, ct);
        if (!current.RequesterCurrent || !current.ActorCanRead) return Results.NotFound();
        if (!IsCurrent(plan, payload, current, now, plans) || !MatchesResolved(resolved, payload, now)) return PlanUnavailable();
        await second.CommitAsync(ct);
        return Results.Ok(ToDto(plan, payload, now, current.ActorCanApprove, actor == payload.RequesterId && current.RequesterCurrent));
    }

    private static async Task<IResult> Approve(
        Guid environmentId,
        Guid planId,
        JsonElement body,
        HttpContext http,
        ConsoleDbContext db,
        IEnrollmentTargetReader reader,
        ChangePlanService plans,
        TimeProvider time,
        ConsoleOptions config,
        CancellationToken ct)
    {
        if (!TryReadApproval(body, out var approvedHash)) return InvalidRequest();
        if (!AuthEndpoints.FreshStepUp(http, time, config)) return Results.Problem(statusCode: 403, title: "StepUpRequired");
        var actor = AuthEndpoints.Actor(http);
        var now = Canonical(time.GetUtcNow());
        EnrollmentGrantPlanPayload payload;
        await using (var first = await db.BeginEnvironment(environmentId, actor, ct))
        {
            var plan = await db.Plans.AsNoTracking().Include(x => x.Items).SingleOrDefaultAsync(x => x.EnvironmentId == environmentId && x.Id == planId, ct);
            if (plan is null || !IsDedicatedAction(plan.Action)) return Results.NotFound();
            var reservation = await db.EnrollmentGrantRecipientReservations.AsNoTracking().SingleOrDefaultAsync(x => x.EnvironmentId == environmentId && x.PlanId == planId, ct);
            if (reservation is null || !TryValidateStored(plan, reservation, out payload)) return PlanUnavailable();
            var access = await ReadAccess(db, environmentId, actor, payload, now, ct);
            if (!access.RequesterCurrent || !access.ActorCanApprove) return Results.NotFound();
            if (!IsCurrent(plan, payload, access, now, plans)) return PlanUnavailable();
        }
        db.ChangeTracker.Clear();

        for (var attempt = 0; ; attempt++)
        {
            db.ChangeTracker.Clear();
            var resolved = await reader.ReadAsync(environmentId, payload.DirectoryObjectId, ct);
            var attemptNow = Canonical(time.GetUtcNow());
            if (!AuthEndpoints.FreshStepUp(http, time, config)) return Results.Problem(statusCode: 403, title: "StepUpRequired");
            if (!MatchesResolved(resolved, payload, attemptNow)) return EnrollmentTargetUnavailable();
            try { return await ApproveAttempt(environmentId, planId, approvedHash, actor, attemptNow, payload, resolved, http, db, plans, time, config, ct); }
            catch (Exception error) when (attempt == 0 && IsSerialization(error)) { }
            catch (Exception error) when (IsSerialization(error)) { return Results.Problem(statusCode: 409, title: "ConcurrentChange"); }
            catch (PostgresException error) when (error.SqlState == "42501") { return Results.NotFound(); }
        }
    }

    private static async Task<IResult> ApproveAttempt(Guid environmentId, Guid planId, string approvedHash, Guid actor,
        DateTimeOffset now, EnrollmentGrantPlanPayload payload, EnrollmentTargetResult resolved, HttpContext http,
        ConsoleDbContext db, ChangePlanService plans, TimeProvider time, ConsoleOptions config, CancellationToken ct)
    {
        await using var tx = await db.BeginEnvironment(environmentId, actor, ct);
        await LockPublicContext(db, environmentId, payload.DirectoryObjectId, [payload.RequesterId, actor], ct);
        await LockPlan(db, environmentId, planId, ct);
        now = Canonical(time.GetUtcNow());
        if (!AuthEndpoints.FreshStepUp(http, time, config)) return Results.Problem(statusCode: 403, title: "StepUpRequired");
        if (!MatchesResolved(resolved, payload, now)) return EnrollmentTargetUnavailable();
        var current = await ReadAccess(db, environmentId, actor, payload, now, ct);
        if (!current.RequesterCurrent || !current.ActorCanApprove) return Results.NotFound();
        var locked = await db.Plans.Include(x => x.Items).SingleOrDefaultAsync(x => x.EnvironmentId == environmentId && x.Id == planId, ct);
        var lockedReservation = await db.EnrollmentGrantRecipientReservations.AsNoTracking().SingleOrDefaultAsync(x => x.EnvironmentId == environmentId && x.PlanId == planId, ct);
        if (locked is null || lockedReservation is null || !IsDedicatedAction(locked.Action) || !TryValidateStored(locked, lockedReservation, out payload)) return PlanUnavailable();
        if (!IsCurrent(locked, payload, current, now, plans) || !MatchesResolved(resolved, payload, now)) return PlanUnavailable();
        if (!FixedEquals(locked.PlanHash, approvedHash)) return Results.Problem(statusCode: 409, title: "ApprovalRejected");

        var existing = await db.Approvals.AsNoTracking().SingleOrDefaultAsync(x => x.EnvironmentId == environmentId && x.PlanId == planId, ct);
        if (locked.State == ChangePlanState.Approved && existing is not null && existing.ApproverId == actor && FixedEquals(existing.PlanHash, approvedHash))
        {
            await tx.CommitAsync(ct);
            return Results.Ok(ToDto(locked, payload, now, canApprove: true, canRequest: false));
        }
        if (locked.State != ChangePlanState.PendingApproval || existing is not null) return Results.Problem(statusCode: 409, title: "ApprovalRejected");

        ChangeApproval approval;
        try { approval = plans.Approve(locked, Guid.NewGuid(), actor, approvedHash, now, locked.ExpiresAt); }
        catch (InvalidOperationException) { return Results.Problem(statusCode: 409, title: "ApprovalRejected"); }
        db.Approvals.Add(approval);
        db.Audit.Add(Audit(http, now, environmentId, actor, "EnrollmentGrantPlan.Approved", locked.Id, "Approved"));
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        return Results.Ok(ToDto(locked, payload, now, canApprove: true, canRequest: false));
    }

    private static async Task<CurrentTarget?> ReadCurrentTarget(ConsoleDbContext db, Guid env, Guid actor, Guid target,
        DateTimeOffset now, CancellationToken ct)
    {
        if (!await db.Principals.AnyAsync(x => x.Id == actor && x.Enabled, ct) ||
            !await db.Memberships.AnyAsync(x => x.EnvironmentId == env && x.PrincipalId == actor && x.Active, ct)) return null;
        var environment = await db.Environments.AsNoTracking().SingleOrDefaultAsync(x => x.Id == env, ct);
        var sync = await db.DirectorySync.AsNoTracking().SingleOrDefaultAsync(x => x.EnvironmentId == env, ct);
        if (environment is null || sync is null) return null;
        var available = sync.Status == "Ready" && sync.CompletedAt is { } completed && completed >= now.AddMinutes(-15) && completed <= now;
        if (!available) return new(environment.Version, sync.Generation, false);
        foreach (var permission in new[] { PermissionCatalog.ComputerView, PermissionCatalog.AgentEnrollmentGrantManage })
        {
            var scoped = await DirectoryApi.Scoped(db, env, actor, permission, sync.Generation, ct);
            if (!await scoped.AnyAsync(x => x.Id == target && x.Kind == "Computer", ct)) return null;
        }
        return new(environment.Version, sync.Generation, true);
    }

    private static async Task<PlanAccess> ReadAccess(ConsoleDbContext db, Guid env, Guid actor,
        EnrollmentGrantPlanPayload payload, DateTimeOffset now, CancellationToken ct)
    {
        var requester = await ReadCurrentTarget(db, env, payload.RequesterId, payload.DirectoryObjectId, now, ct);
        var requesterCurrent = requester is { DirectoryAvailable: true } && requester.Value.EnvironmentVersion == payload.EnvironmentVersion && requester.Value.Generation == payload.DirectoryGeneration;
        if (!requesterCurrent) return new(false, false, false, requester?.EnvironmentVersion, requester?.Generation);
        var requesterValue = requester!.Value;
        if (actor == payload.RequesterId) return new(true, true, false, requesterValue.EnvironmentVersion, requesterValue.Generation);
        if (!await db.Principals.AnyAsync(x => x.Id == actor && x.Enabled, ct) ||
            !await db.Memberships.AnyAsync(x => x.EnvironmentId == env && x.PrincipalId == actor && x.Active, ct))
            return new(true, false, false, requesterValue.EnvironmentVersion, requesterValue.Generation);
        var operators = await db.Principals.Where(x => x.Id == actor || x.Id == payload.RequesterId).Select(x => x.OperatorId).ToListAsync(ct);
        if (operators.Count != 2 || operators.Any(x => x == Guid.Empty) || operators.Distinct().Count() != 2)
            return new(true, false, false, requesterValue.EnvironmentVersion, requesterValue.Generation);
        foreach (var permission in new[] { PermissionCatalog.ComputerView, PermissionCatalog.ChangeApprove })
        {
            var scoped = await DirectoryApi.Scoped(db, env, actor, permission, payload.DirectoryGeneration, ct);
            if (!await scoped.AnyAsync(x => x.Id == payload.DirectoryObjectId && x.Kind == "Computer", ct))
                return new(true, false, false, requesterValue.EnvironmentVersion, requesterValue.Generation);
        }
        return new(true, true, true, requesterValue.EnvironmentVersion, requesterValue.Generation);
    }

    private static bool IsCurrent(ChangePlan plan, EnrollmentGrantPlanPayload payload, PlanAccess access, DateTimeOffset now, ChangePlanService plans) =>
        plan.State is ChangePlanState.PendingApproval or ChangePlanState.Approved && plan.ExpiresAt > now &&
        access.EnvironmentVersion == payload.EnvironmentVersion && access.Generation == payload.DirectoryGeneration &&
        FixedEquals(plan.PlanHash, plans.ComputeHash(plan));

    private static bool ValidResolved(EnrollmentTargetResult result, Guid env, Guid directory, DateTimeOffset now) =>
        result.EnvironmentId == env && result.DirectoryObjectId == directory && result.State == EnrollmentTargetState.Resolved &&
        result.Diagnostic == EnrollmentTargetDiagnostic.None && result.DeviceId is { } device && device != Guid.Empty &&
        result.MappingCreatedAt is { } mapped && mapped.Offset == TimeSpan.Zero && mapped.Ticks % 10 == 0 && mapped <= now;

    private static bool MatchesResolved(EnrollmentTargetResult result, EnrollmentGrantPlanPayload payload, DateTimeOffset now) =>
        ValidResolved(result, payload.EnvironmentId, payload.DirectoryObjectId, now) && result.DeviceId == payload.ServerDeviceId &&
        result.MappingCreatedAt == payload.MappingCreatedAt;

    private static bool TryValidateStored(ChangePlan plan, EnrollmentGrantRecipientReservation reservation, out EnrollmentGrantPlanPayload payload) =>
        ItManagement.AgentEnrollment.Plans.EnrollmentGrantPlanValidation.TryValidateStored(plan, reservation, out payload);

    private static byte[] ComputeRequestDigest(Guid env, Guid requester, Guid request, Guid directory, Guid device,
        DateTimeOffset mappingCreatedAt, long environmentVersion, Guid generation, string spki, string reason) =>
        ItManagement.AgentEnrollment.Plans.EnrollmentGrantPlanValidation.ComputeRequestDigest(env, requester, request, directory,
            device, mappingCreatedAt, environmentVersion, generation, spki, reason);

    private static EnrollmentGrantPlanDto ToDto(ChangePlan plan, EnrollmentGrantPlanPayload payload, DateTimeOffset now, bool canApprove, bool canRequest) =>
        new(plan.Id, plan.EnvironmentId, payload.DirectoryObjectId, plan.RequesterId, payload.RequestId,
            payload.RecipientKeyFingerprint, plan.PlanHash, plan.PolicyVersion, payload.DirectoryGeneration, plan.ExpiresAt,
            now, plan.State.ToString(), payload.Reason, canApprove, canRequest);

    private static bool TryReadRequest(JsonElement body, out ProposalInput input)
    {
        input = default;
        if (body.ValueKind != JsonValueKind.Object || body.EnumerateObject().Count() != 5 ||
            !ExactProperties(body, "requestId", "expectedEnvironmentVersion", "expectedDirectoryGeneration", "recipientSpki", "reason") ||
            !body.TryGetProperty("requestId", out var request) || request.ValueKind != JsonValueKind.String || !request.TryGetGuid(out var requestId) || requestId == Guid.Empty ||
            !body.TryGetProperty("expectedEnvironmentVersion", out var version) || version.ValueKind != JsonValueKind.Number || !version.TryGetInt64(out var environmentVersion) || environmentVersion <= 0 ||
            !body.TryGetProperty("expectedDirectoryGeneration", out var generation) || generation.ValueKind != JsonValueKind.String || !generation.TryGetGuid(out var directoryGeneration) || directoryGeneration == Guid.Empty ||
            !body.TryGetProperty("recipientSpki", out var spki) || spki.ValueKind != JsonValueKind.String || spki.GetString() is not { Length: > 0 and <= 684 } encoded ||
            !body.TryGetProperty("reason", out var reasonElement) || reasonElement.ValueKind != JsonValueKind.String || reasonElement.GetString() is not { Length: >= 5 and <= 512 } reason || reason.Any(char.IsControl)) return false;
        try
        {
            var decoded = DecodeCanonicalBase64Url(encoded);
            input = new(requestId, environmentVersion, directoryGeneration, decoded, reason);
            return true;
        }
        catch (FormatException) { return false; }
    }

    private static bool TryReadApproval(JsonElement body, out string hash)
    {
        hash = string.Empty;
        if (body.ValueKind != JsonValueKind.Object || body.EnumerateObject().Count() != 1 || !ExactProperties(body, "planHash") ||
            !body.TryGetProperty("planHash", out var value) || value.ValueKind != JsonValueKind.String || value.GetString() is not { Length: 64 } text ||
            text.Any(c => c is not (>= '0' and <= '9') and not (>= 'a' and <= 'f'))) return false;
        hash = text;
        return true;
    }

    private static bool ExactProperties(JsonElement body, params string[] expected) =>
        body.EnumerateObject().Select(x => x.Name).Order(StringComparer.Ordinal)
            .SequenceEqual(expected.Order(StringComparer.Ordinal), StringComparer.Ordinal);

    private static byte[] DecodeCanonicalBase64Url(string encoded)
    {
        var bytes = WebEncoders.Base64UrlDecode(encoded);
        if (WebEncoders.Base64UrlEncode(bytes) != encoded) throw new FormatException();
        return bytes;
    }

    private static async Task LockPlan(ConsoleDbContext db, Guid env, Guid plan, CancellationToken ct) =>
        _ = await db.Database.SqlQuery<int>($"SELECT 1 AS \"Value\" FROM public.\"Plans\" WHERE \"EnvironmentId\"={env} AND \"Id\"={plan} FOR UPDATE").SingleOrDefaultAsync(ct);

    private static async Task LockPublicContext(ConsoleDbContext db, Guid env, Guid directory, Guid[] principals, CancellationToken ct)
    {
        principals = principals.Distinct().Order().ToArray();
        await db.Database.ExecuteSqlInterpolatedAsync($"SELECT public.lock_enrollment_grant_plan_context({env},{directory},{principals})", ct);
    }

    private static DateTimeOffset Canonical(DateTimeOffset value) => new(value.UtcTicks - value.UtcTicks % 10, TimeSpan.Zero);
    private static bool FixedEquals(byte[] left, byte[] right) => left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
    private static bool FixedEquals(string left, string right) => FixedEquals(System.Text.Encoding.UTF8.GetBytes(left), System.Text.Encoding.UTF8.GetBytes(right));
    private static bool IsSerialization(Exception error)
    {
        for (Exception? current = error; current is not null; current = current.InnerException)
            if (current is PostgresException { SqlState: "40001" }) return true;
        return false;
    }
    private static AuditRecord Audit(HttpContext http, DateTimeOffset now, Guid env, Guid actor, string action, Guid plan, string result) =>
        new() { EnvironmentId = env, Id = Guid.NewGuid(), ActorId = actor, Action = action, TargetId = plan.ToString(), Result = result,
            OccurredAt = now, SourceIp = http.Connection.RemoteIpAddress?.ToString(), CorrelationId = http.TraceIdentifier };
    private static IResult InvalidRequest() => Results.Problem(statusCode: 400, title: "InvalidEnrollmentGrantPlanRequest");
    private static IResult DirectoryUnavailable() => Results.Problem(statusCode: 503, title: "DirectoryUnavailable");
    private static IResult EnrollmentTargetUnavailable() => Results.Problem(statusCode: 503, title: "EnrollmentTargetUnavailable");
    private static IResult PlanUnavailable() => Results.Problem(statusCode: 409, title: "EnrollmentGrantPlanChangedOrExpired");
    private static IResult RecipientUnavailable() => Results.Problem(statusCode: 409, title: "RecipientKeyUnavailable");

    private readonly record struct ProposalInput(Guid RequestId, long ExpectedEnvironmentVersion, Guid ExpectedDirectoryGeneration, byte[] SubjectPublicKeyInfo, string Reason);
    private readonly record struct CurrentTarget(long EnvironmentVersion, Guid Generation, bool DirectoryAvailable);
    private readonly record struct PlanAccess(bool RequesterCurrent, bool ActorCanRead, bool ActorCanApprove, long? EnvironmentVersion, Guid? Generation);
    private sealed record EnrollmentGrantPlanAuditRow(bool IsValid, string DiagnosticCode, short ProfileVersion);
}
