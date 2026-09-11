using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using ItManagement.Persistence;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace ItManagement.Api;

public static class SessionTokens
{
    public const string Cookie = "__Host-itmanage-session";
    public const string CeremonyCookie = "__Host-itmanage-ceremony";
    public static string New() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    public static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    public static CookieOptions CookieOptions(DateTimeOffset expires) => new()
    { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict, Path = "/", Expires = expires, IsEssential = true };
}

public sealed class SessionAuthentication(
    IOptionsMonitor<AuthenticationSchemeOptions> schemes, ILoggerFactory logger, UrlEncoder encoder,
    ConsoleDbContext db, TimeProvider time, ConsoleOptions config)
    : AuthenticationHandler<AuthenticationSchemeOptions>(schemes, logger, encoder)
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Cookies.TryGetValue(SessionTokens.Cookie, out var token) || token.Length != 64)
            return AuthenticateResult.NoResult();
        var hash = SessionTokens.Hash(token);
        var session = await db.Sessions.AsNoTracking().SingleOrDefaultAsync(x => x.IdHash == hash, Context.RequestAborted);
        var now = time.GetUtcNow();
        if (session is null || session.RevokedAt is not null || session.ExpiresAt <= now ||
            session.LastSeenAt.AddMinutes(config.IdleMinutes) <= now ||
            !await db.Principals.AnyAsync(x => x.Id == session.PrincipalId && x.Enabled, Context.RequestAborted))
            return AuthenticateResult.Fail("Session invalid.");
        // Conditional touch cannot revive an expired or concurrently revoked session.
        var touched = await db.Sessions.Where(x => x.IdHash == hash && x.RevokedAt == null &&
                x.ExpiresAt > now && x.LastSeenAt > now.AddMinutes(-config.IdleMinutes))
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.LastSeenAt, now), Context.RequestAborted);
        if (touched != 1) return AuthenticateResult.Fail("Session invalid.");
        Context.Items[typeof(PlatformSession)] = session;
        var identity = new ClaimsIdentity([
            new Claim(ClaimTypes.NameIdentifier, session.PrincipalId.ToString()),
            new Claim("session", hash), new Claim("auth_method", session.Method)
        ], Scheme.Name);
        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name));
    }
}
