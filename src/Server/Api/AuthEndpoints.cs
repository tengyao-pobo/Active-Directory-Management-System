using System.Security.Claims;
using System.Security.Principal;
using Fido2NetLib;
using Fido2NetLib.Objects;
using ItManagement.Core;
using ItManagement.Persistence;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace ItManagement.Api;

public static class AuthEndpoints
{
    public sealed record LoginRequest(string Username, string Password);
    public sealed record EnrollmentRequest(string Token);
    public sealed record PreferenceRequest(string Locale);

    public static void MapAuth(this WebApplication app)
    {
        var group = app.MapGroup("/api/v1/session");
        group.MapGet("/csrf", (HttpContext http, IAntiforgery csrf) =>
            Results.Ok(new { token = csrf.GetAndStoreTokens(http).RequestToken })).AllowAnonymous();

        group.MapGet("/me", async (HttpContext http, ConsoleDbContext db, CancellationToken ct) =>
        {
            var id = Actor(http);
            return Results.Ok(await db.Principals.Where(x => x.Id == id)
                .Select(x => new { x.Id, x.DisplayName }).SingleAsync(ct));
        });

        group.MapGet("/preferences", async (HttpContext http, ConsoleDbContext db, CancellationToken ct) =>
        {
            var id = Actor(http);
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            await db.Database.ExecuteSqlInterpolatedAsync($"SELECT set_config('app.principal_id', {id.ToString()}, true)", ct);
            var preference = await db.Preferences.AsNoTracking().SingleOrDefaultAsync(x => x.PrincipalId == id, ct);
            return Results.Ok(new { locale = preference?.Locale ?? "zh-TW" });
        });
        group.MapPost("/preferences", async (PreferenceRequest input, HttpContext http, ConsoleDbContext db, TimeProvider time, CancellationToken ct) =>
        {
            if (input.Locale is not ("zh-TW" or "en-US")) return Results.Problem(statusCode: 400, title: "InvalidLocale");
            var id = Actor(http);
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            await db.Database.ExecuteSqlInterpolatedAsync($"SELECT set_config('app.principal_id', {id.ToString()}, true)", ct);
            await db.Database.ExecuteSqlInterpolatedAsync($"INSERT INTO \"Preferences\" (\"PrincipalId\",\"Locale\") VALUES ({id},{input.Locale}) ON CONFLICT (\"PrincipalId\") DO UPDATE SET \"Locale\"=EXCLUDED.\"Locale\"", ct);
            db.SecurityEvents.Add(Event(http, time, id, "LanguagePreferenceChanged", "Success"));
            await db.SaveChangesAsync(ct); await tx.CommitAsync(ct);
            return Results.Ok(new { locale = input.Locale });
        });

        group.MapPost("/logout", async (HttpContext http, ConsoleDbContext db, TimeProvider time, CancellationToken ct) =>
        {
            var hash = http.User.FindFirstValue("session")!;
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            await db.Sessions.Where(x => x.IdHash == hash).ExecuteUpdateAsync(s => s.SetProperty(x => x.RevokedAt, time.GetUtcNow()), ct);
            db.SecurityEvents.Add(Event(http, time, Actor(http), "Logout", "Success"));
            await db.SaveChangesAsync(ct);
            await tx.CommitAsync(ct);
            http.Response.Cookies.Delete(SessionTokens.Cookie, SessionTokens.CookieOptions(time.GetUtcNow()));
            return Results.NoContent();
        });

        group.MapPost("/windows", async (HttpContext http, ConsoleDbContext db, ConsoleOptions config, TimeProvider time, CancellationToken ct) =>
        {
            if (!config.WindowsAuthentication || !OperatingSystem.IsWindows()) return Results.Problem(statusCode: 503, title: "WindowsAuthenticationUnavailable");
            var result = await http.AuthenticateAsync(NegotiateDefaults.AuthenticationScheme);
            if (!result.Succeeded) return Results.Challenge(authenticationSchemes: [NegotiateDefaults.AuthenticationScheme]);
            var identity = result.Principal?.Identity as WindowsIdentity;
            if (identity?.User is null || (config.RequireKerberos && !string.Equals(identity.AuthenticationType, "Kerberos", StringComparison.OrdinalIgnoreCase)))
                return Results.Problem(statusCode: 403, title: "KerberosRequired");
            var sid = identity.User.Value;
            var principal = await db.Principals.SingleOrDefaultAsync(x => x.Issuer == "windows" && x.Subject == sid && x.Enabled, ct);
            if (principal is null)
            {
                db.SecurityEvents.Add(Event(http, time, null, "WindowsLogin", "NotProvisioned"));
                await db.SaveChangesAsync(ct);
                return Results.Problem(statusCode: 403, title: "NotProvisioned");
            }
            await CreateSession(http, db, config, time, principal.Id, "Kerberos", false, ct);
            return Results.NoContent();
        }).AllowAnonymous().RequireRateLimiting("login");

        group.MapPost("/emergency/options", async (LoginRequest input, HttpContext http, ConsoleDbContext db,
            ConsoleOptions config, IPasswordHasher<Principal> hasher, IFido2 fido, TimeProvider time, CancellationToken ct) =>
        {
            if (!EmergencyAllowed(http, config)) return Results.Problem(statusCode: 403, title: "EmergencyLoginUnavailable");
            if (input.Username is not { Length: > 0 and <= 128 } || input.Password is not { Length: > 0 and <= 1024 }) return Results.BadRequest();
            var now = time.GetUtcNow();
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            var principal = await db.Principals.SingleOrDefaultAsync(x => x.Issuer == "local" && x.Subject == input.Username && x.Enabled, ct);
            LocalCredential? credential = null;
            if (principal is not null)
                credential = await db.LocalCredentials.FromSqlInterpolated($"SELECT * FROM \"LocalCredentials\" WHERE \"PrincipalId\"={principal.Id} FOR UPDATE").SingleOrDefaultAsync(ct);
            // Constant-cost verification for unknown names avoids an easy account timing oracle.
            var check = hasher.VerifyHashedPassword(principal ?? new Principal(), credential?.PasswordHash ?? DummyHash.Value, input.Password);
            if (credential is null || credential.LockedUntil > now || check == PasswordVerificationResult.Failed)
            {
                if (credential is not null && credential.LockedUntil <= now || credential is not null && credential.LockedUntil is null)
                {
                    credential.FailedAttempts++;
                    if (credential.FailedAttempts >= 5) credential.LockedUntil = now.AddMinutes(15);
                    credential.Version++;
                }
                db.SecurityEvents.Add(Event(http, time, principal?.Id, "EmergencyLogin", "Denied"));
                await db.SaveChangesAsync(ct); await tx.CommitAsync(ct);
                return Results.Problem(statusCode: 401, title: "AuthenticationFailed");
            }
            var keys = await db.Passkeys.Where(x => x.PrincipalId == principal!.Id && x.RevokedAt == null).ToListAsync(ct);
            if (keys.Count == 0) return Results.Problem(statusCode: 401, title: "AuthenticationFailed");
            credential.FailedAttempts = 0; credential.LockedUntil = null; credential.Version++;
            if (check == PasswordVerificationResult.SuccessRehashNeeded)
                credential.PasswordHash = hasher.HashPassword(principal!, input.Password);
            var options = fido.GetAssertionOptions(new GetAssertionOptionsParams
            { AllowedCredentials = keys.Select(k => new PublicKeyCredentialDescriptor(Convert.FromBase64String(k.CredentialId))).ToArray(), UserVerification = UserVerificationRequirement.Required });
            AddCeremony(http, db, time, principal!.Id, "login", options.ToJson(), null);
            db.SecurityEvents.Add(Event(http, time, principal.Id, "EmergencyPassword", "SecondFactorRequired"));
            await db.SaveChangesAsync(ct); await tx.CommitAsync(ct);
            return Results.Content(options.ToJson(), "application/json");
        }).AllowAnonymous().RequireRateLimiting("login");

        group.MapPost("/step-up/options", async (HttpContext http, ConsoleDbContext db, IFido2 fido, TimeProvider time, CancellationToken ct) =>
        {
            var principal = Actor(http);
            var keys = await db.Passkeys.Where(x => x.PrincipalId == principal && x.RevokedAt == null).ToListAsync(ct);
            if (keys.Count == 0) return Results.Problem(statusCode: 409, title: "PasskeyNotEnrolled");
            var options = fido.GetAssertionOptions(new GetAssertionOptionsParams
            { AllowedCredentials = keys.Select(k => new PublicKeyCredentialDescriptor(Convert.FromBase64String(k.CredentialId))).ToArray(), UserVerification = UserVerificationRequirement.Required });
            AddCeremony(http, db, time, principal, "step-up", options.ToJson(), http.User.FindFirstValue("session"));
            await db.SaveChangesAsync(ct);
            return Results.Content(options.ToJson(), "application/json");
        }).RequireRateLimiting("login");

        group.MapPost("/assertion", Assert).AllowAnonymous().RequireRateLimiting("login");

        group.MapPost("/passkeys/options", async (EnrollmentRequest input, HttpContext http, ConsoleDbContext db,
            ConsoleOptions config, IFido2 fido, TimeProvider time, CancellationToken ct) =>
        {
            if (!EmergencyAllowed(http, config)) return Results.Forbid();
            if (input.Token is not { Length: 64 }) return Results.BadRequest();
            var hash = SessionTokens.Hash(input.Token); var now = time.GetUtcNow();
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            var grant = await db.EnrollmentGrants.SingleOrDefaultAsync(x => x.IdHash == hash, ct);
            if (grant is null || grant.ExpiresAt <= now || grant.ConsumedAt != null) return Results.Forbid();
            if (await db.EnrollmentGrants.Where(x => x.IdHash == hash && x.ConsumedAt == null && x.ExpiresAt > now)
                    .ExecuteUpdateAsync(s => s.SetProperty(x => x.ConsumedAt, now), ct) != 1) return Results.Forbid();
            var principal = await db.Principals.SingleAsync(x => x.Id == grant.PrincipalId && x.Enabled, ct);
            var keys = await db.Passkeys.Where(x => x.PrincipalId == principal.Id).ToListAsync(ct);
            var options = fido.RequestNewCredential(new RequestNewCredentialParams
            {
                User = new Fido2User { Id = principal.Id.ToByteArray(), Name = principal.Subject, DisplayName = principal.DisplayName },
                ExcludeCredentials = keys.Select(k => new PublicKeyCredentialDescriptor(Convert.FromBase64String(k.CredentialId))).ToArray(),
                AuthenticatorSelection = new AuthenticatorSelection { UserVerification = UserVerificationRequirement.Required, ResidentKey = ResidentKeyRequirement.Required },
                AttestationPreference = AttestationConveyancePreference.None
            });
            AddCeremony(http, db, time, principal.Id, "register", options.ToJson(), null);
            db.SecurityEvents.Add(Event(http, time, principal.Id, "PasskeyEnrollment", "Started"));
            await db.SaveChangesAsync(ct); await tx.CommitAsync(ct);
            return Results.Content(options.ToJson(), "application/json");
        }).AllowAnonymous().RequireRateLimiting("login");

        group.MapPost("/passkeys/complete", async (AuthenticatorAttestationRawResponse input, HttpContext http,
            ConsoleDbContext db, ConsoleOptions config, IFido2 fido, TimeProvider time, CancellationToken ct) =>
        {
            if (!EmergencyAllowed(http, config)) return Results.Forbid();
            var ceremony = await TakeCeremony(http, db, time, ct);
            if (ceremony?.Kind != "register") return Results.Problem(statusCode: 401, title: "CeremonyInvalid");
            try
            {
                var result = await fido.MakeNewCredentialAsync(new MakeNewCredentialParams
                {
                    AttestationResponse = input, OriginalOptions = CredentialCreateOptions.FromJson(ceremony.OptionsJson),
                    IsCredentialIdUniqueToUserCallback = async (args, cancel) => !await db.Passkeys.AnyAsync(x => x.CredentialId == Convert.ToBase64String(args.CredentialId), cancel)
                }, ct);
                await using var tx = await db.Database.BeginTransactionAsync(ct);
                if (!await db.Principals.AnyAsync(x => x.Id == ceremony.PrincipalId && x.Enabled, ct)) return Results.Forbid();
                db.Passkeys.Add(new Passkey { PrincipalId = ceremony.PrincipalId, CredentialId = Convert.ToBase64String(result.Id),
                    PublicKey = result.PublicKey, SignCount = result.SignCount, CreatedAt = time.GetUtcNow() });
                db.SecurityEvents.Add(Event(http, time, ceremony.PrincipalId, "PasskeyEnrollment", "Success"));
                await db.SaveChangesAsync(ct); await tx.CommitAsync(ct);
                return Results.NoContent();
            }
            catch (Fido2VerificationException)
            {
                db.SecurityEvents.Add(Event(http, time, ceremony.PrincipalId, "PasskeyEnrollment", "Denied"));
                await db.SaveChangesAsync(ct);
                return Results.Problem(statusCode: 401, title: "AuthenticatorInvalid");
            }
        }).AllowAnonymous().RequireRateLimiting("login");
    }

    private static async Task<IResult> Assert(AuthenticatorAssertionRawResponse input, HttpContext http,
        ConsoleDbContext db, ConsoleOptions config, IFido2 fido, TimeProvider time, CancellationToken ct)
    {
        var ceremony = await TakeCeremony(http, db, time, ct);
        if (ceremony is null || ceremony.Kind is not ("login" or "step-up")) return Results.Problem(statusCode: 401, title: "CeremonyInvalid");
        if (ceremony.Kind == "login" && !EmergencyAllowed(http, config)) return Results.Forbid();
        if (ceremony.Kind == "step-up" && http.User.Identity?.IsAuthenticated != true)
            return Results.Problem(statusCode: 401, title: "SessionInvalid");
        if (ceremony.Kind == "step-up" && (http.User.FindFirstValue("session") != ceremony.SessionHash || Actor(http) != ceremony.PrincipalId)) return Results.Forbid();
        var id = Convert.ToBase64String(input.RawId);
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var key = await db.Passkeys.FromSqlInterpolated($"SELECT * FROM \"Passkeys\" WHERE \"CredentialId\"={id} FOR UPDATE").SingleOrDefaultAsync(ct);
        if (key is null || key.RevokedAt is not null || key.PrincipalId != ceremony.PrincipalId ||
            !await db.Principals.AnyAsync(x => x.Id == key.PrincipalId && x.Enabled, ct)) return Results.Problem(statusCode: 401, title: "AuthenticatorInvalid");
        try
        {
            var verified = await fido.MakeAssertionAsync(new MakeAssertionParams
            {
                AssertionResponse = input, OriginalOptions = AssertionOptions.FromJson(ceremony.OptionsJson),
                StoredPublicKey = key.PublicKey, StoredSignatureCounter = checked((uint)key.SignCount),
                IsUserHandleOwnerOfCredentialIdCallback = (args, _) => Task.FromResult(
                    args.UserHandle.AsSpan().SequenceEqual(key.PrincipalId.ToByteArray()) && args.CredentialId.AsSpan().SequenceEqual(input.RawId))
            }, ct);
            key.SignCount = verified.SignCount; key.Version++;
            if (ceremony.Kind == "login") await CreateSession(http, db, config, time, key.PrincipalId, "EmergencyPasskey", true, ct);
            else
            {
                var now = time.GetUtcNow();
                if (await db.Sessions.Where(x => x.IdHash == ceremony.SessionHash && x.RevokedAt == null && x.ExpiresAt > now)
                    .ExecuteUpdateAsync(s => s.SetProperty(x => x.StepUpAt, now), ct) != 1) return Results.Forbid();
                db.SecurityEvents.Add(Event(http, time, key.PrincipalId, "StepUp", "Success"));
                await db.SaveChangesAsync(ct);
            }
            await tx.CommitAsync(ct);
            return Results.NoContent();
        }
        catch (Fido2VerificationException)
        {
            db.SecurityEvents.Add(Event(http, time, ceremony.PrincipalId, "PasskeyAssertion", "Denied"));
            await db.SaveChangesAsync(ct); await tx.CommitAsync(ct);
            return Results.Problem(statusCode: 401, title: "AuthenticatorInvalid");
        }
    }

    internal static Guid Actor(HttpContext http) => Guid.Parse(http.User.FindFirstValue(ClaimTypes.NameIdentifier)!);
    internal static bool FreshStepUp(HttpContext http, TimeProvider time, ConsoleOptions config) =>
        http.Items[typeof(PlatformSession)] is PlatformSession s && s.StepUpAt is { } at && at > time.GetUtcNow().AddMinutes(-config.StepUpMinutes);
    private static bool EmergencyAllowed(HttpContext http, ConsoleOptions config) => config.EmergencyLogin &&
        http.Connection.RemoteIpAddress is { } remote && config.EmergencyAllowedAddresses.Any(a => System.Net.IPAddress.Parse(a).Equals(remote));
    private static SecurityEvent Event(HttpContext http, TimeProvider time, Guid? principal, string action, string result) =>
        new() { PrincipalId = principal, Action = action, Result = result, OccurredAt = time.GetUtcNow(), SourceIp = http.Connection.RemoteIpAddress?.ToString() ?? "unknown" };
    private static void AddCeremony(HttpContext http, ConsoleDbContext db, TimeProvider time, Guid principal, string kind, string options, string? session)
    {
        var token = SessionTokens.New(); var expires = time.GetUtcNow().AddMinutes(5);
        db.Ceremonies.Add(new AuthCeremony { IdHash = SessionTokens.Hash(token), PrincipalId = principal, Kind = kind, OptionsJson = options, SessionHash = session, ExpiresAt = expires });
        http.Response.Cookies.Append(SessionTokens.CeremonyCookie, token, SessionTokens.CookieOptions(expires));
    }
    private static async Task<AuthCeremony?> TakeCeremony(HttpContext http, ConsoleDbContext db, TimeProvider time, CancellationToken ct)
    {
        if (!http.Request.Cookies.TryGetValue(SessionTokens.CeremonyCookie, out var token) || token.Length != 64) return null;
        var hash = SessionTokens.Hash(token); var now = time.GetUtcNow();
        var ceremony = await db.Ceremonies.AsNoTracking().SingleOrDefaultAsync(x => x.IdHash == hash && x.ConsumedAt == null && x.ExpiresAt > now, ct);
        if (ceremony is null) return null;
        // Commit consumption BEFORE cryptographic validation: a failed ceremony cannot be replayed.
        if (await db.Ceremonies.Where(x => x.IdHash == hash && x.ConsumedAt == null && x.ExpiresAt > now)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.ConsumedAt, now), ct) != 1) return null;
        http.Response.Cookies.Delete(SessionTokens.CeremonyCookie, SessionTokens.CookieOptions(now));
        return ceremony;
    }
    private static async Task CreateSession(HttpContext http, ConsoleDbContext db, ConsoleOptions config, TimeProvider time, Guid principal, string method, bool steppedUp, CancellationToken ct)
    {
        var token = SessionTokens.New(); var now = time.GetUtcNow(); var expires = now.AddMinutes(config.AbsoluteMinutes);
        db.Sessions.Add(new PlatformSession { IdHash = SessionTokens.Hash(token), PrincipalId = principal, Method = method,
            CreatedAt = now, LastSeenAt = now, ExpiresAt = expires, StepUpAt = steppedUp ? now : null,
            SourceIp = http.Connection.RemoteIpAddress?.ToString() ?? "unknown", UserAgent = http.Request.Headers.UserAgent.ToString()[..Math.Min(512, http.Request.Headers.UserAgent.ToString().Length)] });
        db.SecurityEvents.Add(Event(http, time, principal, "Login", method == "EmergencyPasskey" ? "EmergencySuccess" : "Success"));
        await db.SaveChangesAsync(ct);
        http.Response.Cookies.Append(SessionTokens.Cookie, token, SessionTokens.CookieOptions(expires));
    }
    private static class DummyHash
    {
        internal static readonly string Value = new PasswordHasher<Principal>().HashPassword(new Principal(), SessionTokens.New());
    }
}
