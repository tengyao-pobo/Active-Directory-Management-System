using System.Threading.RateLimiting;
using Fido2NetLib;
using ItManagement.Api;
using ItManagement.Core;
using ItManagement.Persistence;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);
var options = builder.Configuration.GetSection("Console").Get<ConsoleOptions>() ?? new();
options.Validate();
var connection = builder.Configuration.GetConnectionString("Console") ?? throw new InvalidOperationException("ConnectionStrings:Console required.");
builder.Services.AddSingleton(options);
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddDbContext<ConsoleDbContext>(o => o.UseNpgsql(connection));
builder.Services.AddScoped<IPasswordHasher<Principal>, PasswordHasher<Principal>>();
builder.Services.Configure<PasswordHasherOptions>(o => o.IterationCount = 210000);
builder.Services.AddSingleton<IFido2>(new Fido2(new Fido2Configuration
{ ServerDomain = options.RelyingPartyId, ServerName = "IT Management Console", Origins = new HashSet<string> { options.Origin }, TimestampDriftTolerance = 0 }));
builder.Services.AddSingleton<AuthorizationEvaluator>();
builder.Services.AddSingleton<ChangePlanService>();
builder.Services.AddScoped<EnvironmentAccess>();
var authentication = builder.Services.AddAuthentication("PlatformSession")
    .AddScheme<AuthenticationSchemeOptions, SessionAuthentication>("PlatformSession", _ => { });
if (options.WindowsAuthentication) authentication.AddNegotiate();
builder.Services.AddAuthorization(o => o.FallbackPolicy = new AuthorizationPolicyBuilder("PlatformSession").RequireAuthenticatedUser().Build());
builder.Services.AddAntiforgery(o =>
{
    o.HeaderName = "X-CSRF-TOKEN"; o.Cookie.Name = "__Host-itmanage-csrf";
    o.Cookie.SecurePolicy = CookieSecurePolicy.Always; o.Cookie.SameSite = SameSiteMode.Strict; o.Cookie.Path = "/";
});
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = 429;
    o.AddPolicy("login", http => RateLimitPartition.GetFixedWindowLimiter(http.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 10, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
});
builder.Services.AddProblemDetails();
builder.WebHost.ConfigureKestrel(o => o.Limits.MaxRequestBodySize = 128 * 1024);
var app = builder.Build();

// Runtime identity must not be able to bypass tenant RLS or own the schema.
await using (var startupScope = app.Services.CreateAsyncScope())
{
    var startupDb = startupScope.ServiceProvider.GetRequiredService<ConsoleDbContext>();
    var unsafeRole = await startupDb.Database.SqlQueryRaw<bool>("""
        SELECT (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR
            EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname='public' AND c.relowner=r.oid AND c.relkind='r')) AS "Value"
        FROM pg_roles r WHERE r.rolname=current_user
        """).SingleAsync();
    if (unsafeRole) throw new InvalidOperationException("API database identity must be a restricted non-owner role without RLS bypass.");
}

app.UseExceptionHandler(handler => handler.Run(async context =>
{
    // Do not expose exception messages, SQL parameters, request bodies or credentials.
    var error = context.Features.Get<Microsoft.AspNetCore.Diagnostics.IExceptionHandlerFeature>()?.Error;
    var status = error is DbUpdateConcurrencyException ? 409 : error is Npgsql.PostgresException { SqlState: "40001" } ? 409 : 503;
    await Results.Problem(statusCode: status, title: status == 409 ? "ConcurrentChange" : "ServiceUnavailable",
        extensions: new Dictionary<string, object?> { ["traceId"] = context.TraceIdentifier }).ExecuteAsync(context);
}));
app.Use(async (context, next) =>
{
    context.Response.Headers.CacheControl = "no-store";
    context.Response.Headers.XContentTypeOptions = "nosniff";
    context.Response.Headers.ContentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    var canonical = new Uri(options.Origin);
    if (!context.Request.IsHttps || !string.Equals(context.Request.Host.Value, canonical.Authority, StringComparison.OrdinalIgnoreCase))
    { context.Response.StatusCode = 400; return; }
    await next();
});
// The public SPA contains no account data. API authorization remains mandatory below.
app.UseWhen(context => !context.Request.Path.StartsWithSegments("/api") &&
    !context.Request.Path.StartsWithSegments("/health"), spa =>
{
    spa.UseDefaultFiles();
    spa.UseStaticFiles();
});
app.UseAuthentication();
app.UseRateLimiter();
app.Use(async (context, next) =>
{
    if (!HttpMethods.IsGet(context.Request.Method) && !HttpMethods.IsHead(context.Request.Method) && !HttpMethods.IsOptions(context.Request.Method))
    {
        if (!string.Equals(context.Request.Headers.Origin, options.Origin, StringComparison.Ordinal))
        { await Results.Problem(statusCode: 403, title: "OriginRejected").ExecuteAsync(context); return; }
        try { await context.RequestServices.GetRequiredService<IAntiforgery>().ValidateRequestAsync(context); }
        catch (AntiforgeryValidationException)
        { await Results.Problem(statusCode: 400, title: "AntiforgeryRejected").ExecuteAsync(context); return; }
    }
    await next();
});
app.UseAuthorization();
app.MapGet("/health/live", () => Results.Ok(new { status = "alive" })).AllowAnonymous();
app.MapAuth();
app.MapEnvironmentApi();
app.MapDirectoryApi();
app.Run();

public partial class Program;
