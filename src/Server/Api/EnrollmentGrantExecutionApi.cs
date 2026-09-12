using System.Text.Json;
using ItManagement.AgentEnrollment.Crypto;
using ItManagement.AgentEnrollmentTargets;
using ItManagement.Core;
using ItManagement.Persistence;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace ItManagement.Api;

public sealed record EnrollmentGrantOperationDto(Guid Id, Guid EnvironmentId, Guid PlanId,
    Guid DirectoryObjectId, string State, DateTimeOffset QueuedAt,
    DateTimeOffset AuthorizationNotAfter, DateTimeOffset QueriedAt);

public static partial class EnrollmentGrantPlanApi
{
    private static async Task<IResult> QueueExecution(Guid environmentId, Guid planId, JsonElement body,
        HttpContext http, ConsoleDbContext db, IEnrollmentTargetReader reader,
        IEnrollmentGrantExecutionReadiness readiness, ChangePlanService plans, TimeProvider time,
        ConsoleOptions config, CancellationToken ct)
    {
        http.Response.Headers.CacheControl = "no-store";
        if (!TryReadApproval(body, out var hash)) return InvalidRequest();
        if (!AuthEndpoints.FreshStepUp(http, time, config)) return Results.Problem(statusCode: 403, title: "StepUpRequired");
        if (!await LockHelperIsValidAsync(db, ct) || !await EnrollmentGrantOperationAudit.IsValidAsync(db, ct)) return ExecutionUnavailable();
        var actor = AuthEndpoints.Actor(http);
        for (var attempt = 0; ; attempt++)
        {
            db.ChangeTracker.Clear();
            try
            {
                EnrollmentGrantPlanPayload payload;
                ChangeApproval expectedApproval;
                await using (var first = await db.BeginEnvironment(environmentId, actor, ct))
                {
                    var plan = await db.Plans.AsNoTracking().Include(x => x.Items)
                        .SingleOrDefaultAsync(x => x.EnvironmentId == environmentId && x.Id == planId, ct);
                    if (plan is null || !IsDedicatedAction(plan.Action) || plan.RequesterId != actor) return Results.NotFound();
                    var reservation = await db.EnrollmentGrantRecipientReservations.AsNoTracking()
                        .SingleOrDefaultAsync(x => x.EnvironmentId == environmentId && x.PlanId == planId, ct);
                    if (reservation is null || !TryValidateStored(plan, reservation, out payload) ||
                        !FixedEquals(plan.PlanHash, hash) || !FixedEquals(plans.ComputeHash(plan), hash)) return ExecutionChanged();
                    if (await ReadCurrentTarget(db, environmentId, actor, payload.DirectoryObjectId, Canonical(time.GetUtcNow()), ct)
                        is not { DirectoryAvailable: true }) return Results.NotFound();
                    if (plan.State == ChangePlanState.Queued)
                    {
                        await LockPublicContext(db, environmentId, payload.DirectoryObjectId, [actor], ct);
                        await LockPlan(db, environmentId, planId, ct);
                        var retryNow = Canonical(time.GetUtcNow());
                        var retryDeadline = await CurrentStepUpDeadline(db, http, actor, retryNow, config, ct);
                        retryNow = Canonical(time.GetUtcNow());
                        if (retryDeadline is null || retryDeadline <= retryNow)
                            return Results.Problem(statusCode: 403, title: "StepUpRequired");
                        if (await ReadCurrentTarget(db, environmentId, actor, payload.DirectoryObjectId, retryNow, ct)
                            is not { DirectoryAvailable: true }) return Results.NotFound();
                        var retry = await ReadQueuedOperation(db, plan, payload, hash, retryNow, ct);
                        await first.CommitAsync(ct);
                        return retry;
                    }
                    expectedApproval = await db.Approvals.AsNoTracking()
                        .SingleOrDefaultAsync(x => x.EnvironmentId == environmentId && x.PlanId == planId, ct) ?? null!;
                    var now = Canonical(time.GetUtcNow());
                    if (plan.State != ChangePlanState.Approved || expectedApproval is null ||
                        !ApprovalMatches(expectedApproval, plan, now)) return ExecutionChanged();
                    var access = await ReadAccess(db, environmentId, expectedApproval.ApproverId, payload, now, ct);
                    if (!access.RequesterCurrent || !access.ActorCanApprove || !IsCurrent(plan, payload, access, now, plans))
                        return ExecutionChanged();
                    if (!readiness.IsReady(environmentId)) return ExecutionUnavailable();
                    await first.CommitAsync(ct);
                }
                db.ChangeTracker.Clear();
                var resolved = await reader.ReadAsync(environmentId, payload.DirectoryObjectId, ct);
                if (!MatchesResolved(resolved, payload, Canonical(time.GetUtcNow()))) return EnrollmentTargetUnavailable();
                await using var final = await db.BeginEnvironment(environmentId, actor, ct);
                await LockPublicContext(db, environmentId, payload.DirectoryObjectId, [actor, expectedApproval.ApproverId], ct);
                await LockPlan(db, environmentId, planId, ct);
                var finalNow = Canonical(time.GetUtcNow());
                var stepUpDeadline = await CurrentStepUpDeadline(db, http, actor, finalNow, config, ct);
                // Session row acquisition may wait; all time-dependent assertions use the new clock.
                finalNow = Canonical(time.GetUtcNow());
                if (stepUpDeadline is null || stepUpDeadline <= finalNow)
                    return Results.Problem(statusCode: 403, title: "StepUpRequired");
                var locked = await db.Plans.Include(x => x.Items)
                    .SingleOrDefaultAsync(x => x.EnvironmentId == environmentId && x.Id == planId, ct);
                var lockedReservation = await db.EnrollmentGrantRecipientReservations.AsNoTracking()
                    .SingleOrDefaultAsync(x => x.EnvironmentId == environmentId && x.PlanId == planId, ct);
                if (locked is null || lockedReservation is null || !TryValidateStored(locked, lockedReservation, out var currentPayload) ||
                    currentPayload != payload || !FixedEquals(locked.PlanHash, hash) ||
                    !FixedEquals(plans.ComputeHash(locked), hash)) return ExecutionChanged();
                if (await ReadCurrentTarget(db, environmentId, actor, payload.DirectoryObjectId, finalNow, ct)
                    is not { DirectoryAvailable: true }) return Results.NotFound();
                if (locked.State == ChangePlanState.Queued)
                {
                    var retry = await ReadQueuedOperation(db, locked, payload, hash, finalNow, ct);
                    await final.CommitAsync(ct);
                    return retry;
                }
                var approval = await db.Approvals.AsNoTracking()
                    .SingleOrDefaultAsync(x => x.EnvironmentId == environmentId && x.PlanId == planId, ct);
                if (locked.State != ChangePlanState.Approved || approval is null ||
                    !SameApproval(approval, expectedApproval) || !ApprovalMatches(approval, locked, finalNow)) return ExecutionChanged();
                var currentAccess = await ReadAccess(db, environmentId, approval.ApproverId, payload, finalNow, ct);
                if (!currentAccess.RequesterCurrent || !currentAccess.ActorCanApprove ||
                    !IsCurrent(locked, payload, currentAccess, finalNow, plans) || !MatchesResolved(resolved, payload, finalNow))
                    return ExecutionChanged();
                if (!readiness.IsReady(environmentId)) return ExecutionUnavailable();
                if (await db.EnrollmentGrantOperations.AnyAsync(x => x.EnvironmentId == environmentId && x.PlanId == planId, ct) ||
                    await db.Outbox.AnyAsync(x => x.EnvironmentId == environmentId && x.Id == payload.OperationId, ct)) return ExecutionChanged();
                var people = await db.Principals.AsNoTracking().Where(x => x.Id == actor || x.Id == approval.ApproverId)
                    .ToDictionaryAsync(x => x.Id, x => x.OperatorId, ct);
                if (people.Count != 2 || people.Values.Any(x => x == Guid.Empty) || people.Values.Distinct().Count() != 2)
                    return ExecutionChanged();
                var deadline = new[] { locked.ExpiresAt, approval.ExpiresAt, stepUpDeadline.Value }.Min();
                var key = EnrollmentGrantRecipientKey.Validate(DecodeCanonicalBase64Url(payload.RecipientSpki));
                var lateAccess = await ReadAccess(db, environmentId, approval.ApproverId, payload, Canonical(time.GetUtcNow()), ct);
                var completedAt = await db.DirectorySync.AsNoTracking().Where(x => x.EnvironmentId == environmentId)
                    .Select(x => x.CompletedAt).SingleAsync(ct);
                if (!readiness.IsReady(environmentId)) return ExecutionUnavailable();
                finalNow = Canonical(time.GetUtcNow());
                // Context locks keep the captured authorization facts stable; freshness still ages while queries wait.
                if (deadline <= finalNow || !ApprovalMatches(approval, locked, finalNow) ||
                    !lateAccess.RequesterCurrent || !lateAccess.ActorCanApprove ||
                    !IsCurrent(locked, payload, lateAccess, finalNow, plans) ||
                    completedAt is null || completedAt > finalNow || completedAt < finalNow.AddMinutes(-15)) return ExecutionChanged();
                var operation = new EnrollmentGrantOperation
                {
                    EnvironmentId = environmentId, Id = payload.OperationId, PlanId = planId, RequestId = payload.RequestId,
                    ApprovalId = approval.Id, RequesterId = actor, ApproverId = approval.ApproverId,
                    RequesterOperatorId = people[actor], ApproverOperatorId = people[approval.ApproverId], PlanHash = hash,
                    DirectoryObjectId = payload.DirectoryObjectId, ServerDeviceId = payload.ServerDeviceId,
                    MappingCreatedAt = payload.MappingCreatedAt, DirectoryGeneration = payload.DirectoryGeneration,
                    EnvironmentVersion = payload.EnvironmentVersion, RecipientSpki = key.GetSubjectPublicKeyInfo(),
                    RecipientKeyFingerprint = key.GetFingerprintSha256(), QueuedAt = finalNow, AuthorizationNotAfter = deadline
                };
                locked.State = ChangePlanState.Queued;
                await db.SaveChangesAsync(ct);
                db.EnrollmentGrantOperations.Add(operation);
                db.Outbox.Add(new OutboxMessage { EnvironmentId = environmentId, Id = operation.Id,
                    EventType = EnrollmentGrantOperationContract.OutboxEvent, Version = EnrollmentGrantOperationContract.SchemaVersion,
                    Payload = JsonSerializer.Serialize(new EnrollmentGrantExecutionNotification(1, environmentId, operation.Id), StrictJson), CreatedAt = finalNow });
                db.Audit.Add(Audit(http, finalNow, environmentId, actor, "EnrollmentGrantExecution.Queued", planId, "Queued"));
                await db.SaveChangesAsync(ct);
                await final.CommitAsync(ct);
                return Results.Accepted(value: OperationDto(operation, finalNow));
            }
            catch (Exception error) when (attempt == 0 && IsSerialization(error)) { }
            catch (Exception error) when (IsSerialization(error)) { return Results.Problem(statusCode: 409, title: "ConcurrentChange"); }
            catch (PostgresException error) when (error.SqlState == "42501") { return Results.NotFound(); }
        }
    }

    private static async Task<IResult> ReadExecution(Guid environmentId, Guid operationId, HttpContext http,
        ConsoleDbContext db, TimeProvider time, CancellationToken ct)
    {
        http.Response.Headers.CacheControl = "no-store";
        var actor = AuthEndpoints.Actor(http);
        await using var tx = await db.BeginEnvironment(environmentId, actor, ct);
        if (!await LockHelperIsValidAsync(db, ct) || !await EnrollmentGrantOperationAudit.IsValidAsync(db, ct)) return ExecutionUnavailable();
        var operation = await db.EnrollmentGrantOperations.AsNoTracking()
            .SingleOrDefaultAsync(x => x.EnvironmentId == environmentId && x.Id == operationId && x.RequesterId == actor, ct);
        var now = Canonical(time.GetUtcNow());
        if (operation is null || await ReadCurrentTarget(db, environmentId, actor, operation.DirectoryObjectId, now, ct)
            is not { DirectoryAvailable: true }) return Results.NotFound();
        await tx.CommitAsync(ct);
        return Results.Ok(OperationDto(operation, now));
    }

    private static async Task<IResult> ReadQueuedPlan(ConsoleDbContext db, ChangePlan plan,
        EnrollmentGrantPlanPayload payload, Guid actor, DateTimeOffset now, ChangePlanService plans, CancellationToken ct)
    {
        if (actor != payload.RequesterId || await ReadCurrentTarget(db, plan.EnvironmentId, actor, payload.DirectoryObjectId, now, ct)
            is not { DirectoryAvailable: true }) return Results.NotFound();
        if (!await LockHelperIsValidAsync(db, ct) || !await EnrollmentGrantOperationAudit.IsValidAsync(db, ct)) return ExecutionUnavailable();
        if (!FixedEquals(plans.ComputeHash(plan), plan.PlanHash)) return ExecutionChanged();
        var integrity = await ReadQueuedOperation(db, plan, payload, plan.PlanHash, now, ct);
        if (integrity is not IStatusCodeHttpResult { StatusCode: 200 }) return integrity;
        return Results.Ok(ToDto(plan, payload, now, canApprove: false, canRequest: false));
    }

    private static async Task<IResult> ReadQueuedOperation(ConsoleDbContext db, ChangePlan plan,
        EnrollmentGrantPlanPayload payload, string hash, DateTimeOffset now, CancellationToken ct)
    {
        var operation = await db.EnrollmentGrantOperations.AsNoTracking()
            .SingleOrDefaultAsync(x => x.EnvironmentId == plan.EnvironmentId && x.PlanId == plan.Id, ct);
        if (plan.State != ChangePlanState.Queued || operation is null || operation.Id != payload.OperationId ||
            operation.RequesterId != payload.RequesterId || operation.RequestId != payload.RequestId ||
            operation.PlanHash != hash || operation.DirectoryObjectId != payload.DirectoryObjectId ||
            operation.ServerDeviceId != payload.ServerDeviceId || operation.MappingCreatedAt != payload.MappingCreatedAt ||
            operation.DirectoryGeneration != payload.DirectoryGeneration || operation.EnvironmentVersion != payload.EnvironmentVersion ||
            !FixedEquals(operation.RecipientSpki, DecodeCanonicalBase64Url(payload.RecipientSpki)) ||
            !FixedEquals(operation.RecipientKeyFingerprint, DecodeCanonicalBase64Url(payload.RecipientKeyFingerprint))) return ExecutionChanged();
        var outbox = await db.Outbox.AsNoTracking().SingleOrDefaultAsync(x => x.EnvironmentId == plan.EnvironmentId && x.Id == operation.Id, ct);
        if (outbox is null || outbox.EventType != EnrollmentGrantOperationContract.OutboxEvent || outbox.Version != 1 ||
            outbox.CreatedAt != operation.QueuedAt) return ExecutionChanged();
        try
        {
            var notification = JsonSerializer.Deserialize<EnrollmentGrantExecutionNotification>(outbox.Payload, StrictJson);
            if (notification != new EnrollmentGrantExecutionNotification(1, plan.EnvironmentId, operation.Id)) return ExecutionChanged();
        }
        catch (JsonException) { return ExecutionChanged(); }
        return Results.Ok(OperationDto(operation, now));
    }

    private static async Task<DateTimeOffset?> CurrentStepUpDeadline(ConsoleDbContext db, HttpContext http, Guid actor,
        DateTimeOffset now, ConsoleOptions config, CancellationToken ct)
    {
        if (http.Items[typeof(PlatformSession)] is not PlatformSession authenticated) return null;
        var session = await db.Sessions.FromSqlInterpolated(
            $"SELECT * FROM public.\"Sessions\" WHERE \"IdHash\"={authenticated.IdHash} FOR SHARE").AsNoTracking().SingleOrDefaultAsync(ct);
        if (session is null || session.PrincipalId != actor || session.RevokedAt is not null || session.ExpiresAt <= now ||
            session.StepUpAt is not { } at || at > now || at < session.CreatedAt) return null;
        try
        {
            var deadline = Canonical(new[] { at.AddMinutes(config.StepUpMinutes), session.ExpiresAt }.Min());
            return deadline > now && deadline < DateTimeOffset.MaxValue ? deadline : null;
        }
        catch (ArgumentOutOfRangeException) { return null; }
    }

    private static bool ApprovalMatches(ChangeApproval approval, ChangePlan plan, DateTimeOffset now) =>
        approval.EnvironmentId == plan.EnvironmentId && approval.PlanId == plan.Id && approval.ApproverId != plan.RequesterId &&
        FixedEquals(approval.PlanHash, plan.PlanHash) && approval.ApprovedAt <= now &&
        approval.ApprovedAt < approval.ExpiresAt && approval.ExpiresAt > now && approval.ExpiresAt <= plan.ExpiresAt;

    private static bool SameApproval(ChangeApproval left, ChangeApproval right) =>
        left.Id == right.Id && left.EnvironmentId == right.EnvironmentId && left.PlanId == right.PlanId &&
        left.ApproverId == right.ApproverId && left.PlanHash == right.PlanHash &&
        left.ApprovedAt == right.ApprovedAt && left.ExpiresAt == right.ExpiresAt;

    private static EnrollmentGrantOperationDto OperationDto(EnrollmentGrantOperation value, DateTimeOffset now) =>
        new(value.Id, value.EnvironmentId, value.PlanId, value.DirectoryObjectId, "Queued", value.QueuedAt, value.AuthorizationNotAfter, now);
    private static IResult ExecutionChanged() => Results.Problem(statusCode: 409, title: "EnrollmentGrantExecutionChanged");
    private static IResult ExecutionUnavailable() => Results.Problem(statusCode: 503, title: "EnrollmentGrantExecutionUnavailable");
}
