namespace ItManagement.IntegrationTests;

[Collection(nameof(PostgresApiCollection))]
public sealed class Phase3Tests(PostgresApiFixture fixture)
{
    private const string Path = "/api/v1/session/preferences";

    [Fact]
    public async Task Language_preference_persists_only_for_current_principal()
    {
        var data = await fixture.SeedAsync();
        using var first = fixture.Client(data.RequesterToken);
        using var other = fixture.Client(data.ViewerToken);
        Assert.Equal("zh-TW", (await first.GetFromJsonAsync<JsonElement>(Path)).GetProperty("locale").GetString());
        using var request = await first.MutationAsync(HttpMethod.Post, Path, new { locale = "en-US", principalId = data.Viewer.Id });
        Assert.Equal(HttpStatusCode.OK, (await first.SendAsync(request)).StatusCode);
        Assert.Equal("en-US", (await first.GetFromJsonAsync<JsonElement>(Path)).GetProperty("locale").GetString());
        Assert.Equal("zh-TW", (await other.GetFromJsonAsync<JsonElement>(Path)).GetProperty("locale").GetString());

        await using var db = new ConsoleDbContext(new DbContextOptionsBuilder<ConsoleDbContext>()
            .UseNpgsql(Environment.GetEnvironmentVariable("CONSOLE_TEST_RUNTIME_DB")!).Options);
        Assert.Empty(await db.Preferences.ToListAsync());
        await using var tx = await db.Database.BeginTransactionAsync();
        await db.Database.ExecuteSqlInterpolatedAsync($"SELECT set_config('app.principal_id', {data.Viewer.Id.ToString()}, true)");
        Assert.Empty(await db.Preferences.Where(p => p.PrincipalId == data.Requester.Id).ToListAsync());
    }

    [Theory]
    [InlineData("fr-FR")]
    [InlineData(null)]
    public async Task Unsupported_language_is_rejected(string? locale)
    {
        var data = await fixture.SeedAsync();
        using var client = fixture.Client(data.ViewerToken);
        using var request = await client.MutationAsync(HttpMethod.Post, Path, new { locale });
        Assert.Equal(HttpStatusCode.BadRequest, (await client.SendAsync(request)).StatusCode);
    }

    [Fact]
    public async Task Preference_write_requires_session_origin_and_csrf()
    {
        using var anonymous = fixture.Client();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync(Path)).StatusCode);
        var data = await fixture.SeedAsync();
        using var client = fixture.Client(data.ViewerToken);
        using var wrongOrigin = await client.MutationAsync(HttpMethod.Post, Path, new { locale = "en-US" }, "https://other.invalid");
        Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(wrongOrigin)).StatusCode);
        using var missing = new HttpRequestMessage(HttpMethod.Post, Path) { Content = JsonContent.Create(new { locale = "en-US" }) };
        missing.Headers.Add("Origin", "https://localhost:7443");
        Assert.Equal(HttpStatusCode.BadRequest, (await client.SendAsync(missing)).StatusCode);
    }

    [Fact]
    public async Task Static_assets_cannot_shadow_api_or_health_routes()
    {
        var directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "itmc-static-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(System.IO.Path.Combine(directory, "api/v1/session/me"));
        Directory.CreateDirectory(System.IO.Path.Combine(directory, "health"));
        await File.WriteAllTextAsync(System.IO.Path.Combine(directory, "index.html"), "<html>public console</html>");
        await File.WriteAllTextAsync(System.IO.Path.Combine(directory, "api/v1/session/me/index.html"), "spoofed identity");
        await File.WriteAllTextAsync(System.IO.Path.Combine(directory, "health/live"), "spoofed health");
        try
        {
            using var factory = fixture.Factory.WithWebHostBuilder(builder => builder.UseEnvironment("Production").UseWebRoot(directory));
            using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost:7443"), AllowAutoRedirect = false });
            var index = await client.GetAsync("/");
            Assert.Equal(HttpStatusCode.OK, index.StatusCode);
            Assert.Contains("public console", await index.Content.ReadAsStringAsync());
            Assert.DoesNotContain("unsafe-inline", index.Headers.GetValues("Content-Security-Policy").Single());
            Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/v1/session/me")).StatusCode);
            Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/v1/session/me/")).StatusCode);
            Assert.Equal("alive", (await client.GetFromJsonAsync<JsonElement>("/health/live")).GetProperty("status").GetString());
        }
        finally { Directory.Delete(directory, recursive: true); }
    }
}
