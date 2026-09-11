using System.Buffers.Binary;
using System.Formats.Cbor;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Fido2NetLib;
using Fido2NetLib.Objects;
using ItManagement.Api;
using ItManagement.Core;
using ItManagement.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

[assembly: CollectionBehavior(DisableTestParallelization = true)]
namespace ItManagement.SecurityTests;

// Software test authenticator creates real P-256 COSE keys, CBOR attestation and WebAuthn signatures.
// It exercises the real HTTP handlers and Fido2 verifier, not a mock verifier or an auth test scheme.
public sealed class WebAuthnFlowTests
{
    [Theory]
    [InlineData("valid")]
    [InlineData("wrong-origin")]
    [InlineData("wrong-challenge")]
    [InlineData("missing-uv")]
    [InlineData("invalid-signature")]
    public async Task Emergency_login_requires_valid_password_and_bound_cryptographic_assertion(string mode)
    {
        var connection = Environment.GetEnvironmentVariable("CONSOLE_TEST_DB") ?? throw new InvalidOperationException("CONSOLE_TEST_DB required");
        var runtime = Environment.GetEnvironmentVariable("CONSOLE_TEST_RUNTIME_DB") ?? throw new InvalidOperationException("Restricted runtime DB required");
        Environment.SetEnvironmentVariable("ConnectionStrings__Console", runtime);
        Environment.SetEnvironmentVariable("Console__EmergencyLogin", "true");
        Environment.SetEnvironmentVariable("Console__EmergencyAllowedAddresses__0", "127.0.0.1");
        await using var db = new ConsoleDbContext(new DbContextOptionsBuilder<ConsoleDbContext>().UseNpgsql(connection).Options);
        await db.Database.MigrateAsync();
        var principal = new Principal { Id = Guid.NewGuid(), OperatorId = Guid.NewGuid(), Issuer = "local", Subject = "synthetic-" + Guid.NewGuid().ToString("N"), DisplayName = "Synthetic operator", Enabled = true };
        var password = SessionTokens.New(); var grant = SessionTokens.New();
        db.Principals.Add(principal);
        db.LocalCredentials.Add(new LocalCredential { PrincipalId = principal.Id, PasswordHash = new PasswordHasher<Principal>().HashPassword(principal, password) });
        db.EnrollmentGrants.Add(new PasskeyEnrollmentGrant { IdHash = SessionTokens.Hash(grant), PrincipalId = principal.Id, ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5) });
        await db.SaveChangesAsync();
        await using var factory = new PasskeyFactory();
        using var rawClient = factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost:7443"), HandleCookies = false, AllowAutoRedirect = false });
        var client = new Browser(rawClient);
        using var authenticator = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var credentialId = RandomNumberGenerator.GetBytes(32);

        var begin = await client.Post("/api/v1/session/passkeys/options", new { token = grant });
        Assert.True(begin.StatusCode == HttpStatusCode.OK, $"Enrollment returned {begin.StatusCode}: {await begin.Content.ReadAsStringAsync()}; configured emergency={factory.Services.GetRequiredService<ConsoleOptions>().EmergencyLogin}");
        var creation = CredentialCreateOptions.FromJson(await begin.Content.ReadAsStringAsync());
        var registration = Registration(authenticator, credentialId, creation.Challenge);
        var finish = await client.Post("/api/v1/session/passkeys/complete", registration);
        Assert.Equal(HttpStatusCode.NoContent, finish.StatusCode);
        Assert.False(client.Cookies.ContainsKey(SessionTokens.Cookie));

        var login = await client.Post("/api/v1/session/emergency/options", new { username = principal.Subject, password });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        Assert.False(client.Cookies.ContainsKey(SessionTokens.Cookie)); // Password alone never authenticates.
        var assertionOptions = AssertionOptions.FromJson(await login.Content.ReadAsStringAsync());
        var assertion = Assertion(authenticator, principal.Id, credentialId, assertionOptions.Challenge, mode);
        var response = await client.Post("/api/v1/session/assertion", assertion);
        Assert.Equal(mode == "valid" ? HttpStatusCode.NoContent : HttpStatusCode.Unauthorized, response.StatusCode);
        if (mode == "valid")
        {
            Assert.True(client.Cookies.ContainsKey(SessionTokens.Cookie));
            var me = await client.Get("/api/v1/session/me");
            Assert.Equal(HttpStatusCode.OK, me.StatusCode);
            Assert.Contains(principal.Id.ToString(), await me.Content.ReadAsStringAsync());
            var key = await db.Passkeys.AsNoTracking().SingleAsync(x => x.PrincipalId == principal.Id);
            Assert.Equal(1, key.SignCount);
        }
        else Assert.False(client.Cookies.ContainsKey(SessionTokens.Cookie));
        // Used or failed ceremony is consumed. The same signature cannot be submitted twice.
        var replay = await client.Post("/api/v1/session/assertion", assertion);
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
        Assert.True(await db.SecurityEvents.AnyAsync(x => x.PrincipalId == principal.Id));
    }

    private static AuthenticatorAttestationRawResponse Registration(ECDsa key, byte[] id, byte[] challenge)
    {
        var publicKey = key.ExportParameters(false);
        var cose = new CborWriter(); cose.WriteStartMap(5);
        cose.WriteInt32(1); cose.WriteInt32(2); // EC2
        cose.WriteInt32(3); cose.WriteInt32(-7); // ES256
        cose.WriteInt32(-1); cose.WriteInt32(1); // P-256
        cose.WriteInt32(-2); cose.WriteByteString(publicKey.Q.X!);
        cose.WriteInt32(-3); cose.WriteByteString(publicKey.Q.Y!); cose.WriteEndMap();
        var auth = new List<byte>(AuthData(0x45, 0)); // UP + UV + AT
        auth.AddRange(new byte[16]);
        auth.Add((byte)(id.Length >> 8)); auth.Add((byte)id.Length); auth.AddRange(id); auth.AddRange(cose.Encode());
        var attestation = new CborWriter(); attestation.WriteStartMap(3);
        attestation.WriteTextString("fmt"); attestation.WriteTextString("none");
        attestation.WriteTextString("attStmt"); attestation.WriteStartMap(0); attestation.WriteEndMap();
        attestation.WriteTextString("authData"); attestation.WriteByteString(auth.ToArray()); attestation.WriteEndMap();
        return new AuthenticatorAttestationRawResponse
        {
            Id = B64(id), RawId = id, Type = PublicKeyCredentialType.PublicKey, ClientExtensionResults = new(),
            Response = new AuthenticatorAttestationRawResponse.AttestationResponse
            { AttestationObject = attestation.Encode(), ClientDataJson = ClientData("webauthn.create", challenge, "https://localhost:7443"), Transports = [AuthenticatorTransport.Internal] }
        };
    }
    private static AuthenticatorAssertionRawResponse Assertion(ECDsa key, Guid principal, byte[] id, byte[] challenge, string mode)
    {
        var data = ClientData("webauthn.get", mode == "wrong-challenge" ? RandomNumberGenerator.GetBytes(32) : challenge,
            mode == "wrong-origin" ? "https://attacker.invalid" : "https://localhost:7443");
        var auth = AuthData(mode == "missing-uv" ? (byte)0x01 : (byte)0x05, 1);
        var message = auth.Concat(SHA256.HashData(data)).ToArray();
        var signature = key.SignData(message, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        if (mode == "invalid-signature") signature[^1] ^= 1;
        return new AuthenticatorAssertionRawResponse
        {
            Id = B64(id), RawId = id, Type = PublicKeyCredentialType.PublicKey, ClientExtensionResults = new(),
            Response = new AuthenticatorAssertionRawResponse.AssertionResponse
            { AuthenticatorData = auth, ClientDataJson = data, Signature = signature, UserHandle = principal.ToByteArray() }
        };
    }
    private static byte[] AuthData(byte flags, uint count)
    {
        var data = new byte[37]; SHA256.HashData(Encoding.UTF8.GetBytes("localhost")).CopyTo(data, 0);
        data[32] = flags; BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(33), count); return data;
    }
    private static byte[] ClientData(string type, byte[] challenge, string origin) => JsonSerializer.SerializeToUtf8Bytes(new { type, challenge = B64(challenge), origin, crossOrigin = false });
    private static string B64(byte[] data) => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

internal sealed class PasskeyFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Console:Origin"] = "https://localhost:7443", ["Console:RelyingPartyId"] = "localhost",
            ["Console:WindowsAuthentication"] = "false", ["Console:EmergencyLogin"] = "true",
            ["Console:EmergencyAllowedAddresses:0"] = "127.0.0.1"
        }));
        builder.ConfigureServices(services => services.AddSingleton<IStartupFilter, LoopbackFilter>());
    }
    private sealed class LoopbackFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        { app.Use((http, continuation) => { http.Connection.RemoteIpAddress = IPAddress.Loopback; return continuation(); }); next(app); };
    }
}
internal sealed class Browser(HttpClient client)
{
    public Dictionary<string, string> Cookies { get; } = new();
    public async Task<HttpResponseMessage> Get(string path) => await Send(new HttpRequestMessage(HttpMethod.Get, path));
    public async Task<HttpResponseMessage> Post(string path, object body)
    {
        var csrf = await Get("/api/v1/session/csrf"); csrf.EnsureSuccessStatusCode();
        var token = JsonDocument.Parse(await csrf.Content.ReadAsStringAsync()).RootElement.GetProperty("token").GetString();
        var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = JsonContent.Create(body, body.GetType()) };
        request.Headers.Add("Origin", "https://localhost:7443"); request.Headers.Add("X-CSRF-TOKEN", token);
        return await Send(request);
    }
    private async Task<HttpResponseMessage> Send(HttpRequestMessage request)
    {
        if (Cookies.Count > 0) request.Headers.Add("Cookie", string.Join("; ", Cookies.Select(p => p.Key + "=" + p.Value)));
        var response = await client.SendAsync(request);
        if (response.Headers.TryGetValues("Set-Cookie", out var values))
            foreach (var value in values)
            {
                var pair = value.Split(';')[0].Split('=', 2);
                if (pair[1].Length == 0) Cookies.Remove(pair[0]); else Cookies[pair[0]] = pair[1];
            }
        return response;
    }
}
