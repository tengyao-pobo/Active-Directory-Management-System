namespace ItManagement.AgentIngestion;

public sealed class AttestedAgentPeer
{
    private readonly byte[] _leafDerSha256;

    private AttestedAgentPeer(byte[] leafDerSha256)
    {
        _leafDerSha256 = leafDerSha256;
    }

    internal static AttestedAgentPeer FromValidatedChannel(ReadOnlySpan<byte> leafDerSha256)
    {
        if (leafDerSha256.Length != 32)
        {
            throw new ArgumentException("A SHA-256 certificate fingerprint must contain exactly 32 bytes.", nameof(leafDerSha256));
        }

        return new AttestedAgentPeer(leafDerSha256.ToArray());
    }

    public byte[] GetLeafDerSha256() => (byte[])_leafDerSha256.Clone();
}
