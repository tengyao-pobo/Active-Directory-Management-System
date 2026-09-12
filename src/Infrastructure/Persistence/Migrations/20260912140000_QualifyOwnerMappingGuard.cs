using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using System.Security.Cryptography;
using System.Text;

namespace ItManagement.Persistence.Migrations;

[DbContext(typeof(ConsoleDbContext))]
[Migration("20260912140000_QualifyOwnerMappingGuard")]
public sealed class QualifyOwnerMappingGuard : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        using var source = typeof(QualifyOwnerMappingGuard).Assembly.GetManifestResourceStream("ItManagement.Persistence.OwnerMappingGuard.sql")
            ?? throw new InvalidOperationException("Owner mapping guard migration resource is missing.");
        using var reader = new StreamReader(source);
        var sql = reader.ReadToEnd().Replace("\r\n", "\n", StringComparison.Ordinal);
        var hash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(sql)));
        if (hash != "f13a264b726ce26f763acb5d7b684e86fda1a6c9d62f9f515908a38079b616f3")
            throw new InvalidOperationException("Owner mapping guard migration resource has changed.");
        migrationBuilder.Sql(sql);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Use a reviewed forward migration; do not restore the unqualified Owner mapping guard.");
}
