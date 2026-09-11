namespace ItManagement.Api;

public sealed class ConsoleOptions
{
    public string Origin { get; set; } = "https://localhost:7443";
    public string RelyingPartyId { get; set; } = "localhost";
    public bool WindowsAuthentication { get; set; }
    public bool RequireKerberos { get; set; } = true;
    public bool EmergencyLogin { get; set; }
    public string[] EmergencyAllowedAddresses { get; set; } = [];
    public int IdleMinutes { get; set; } = 20;
    public int AbsoluteMinutes { get; set; } = 480;
    public int StepUpMinutes { get; set; } = 5;

    public void Validate()
    {
        if (!Uri.TryCreate(Origin, UriKind.Absolute, out var origin) || origin.Scheme != "https" ||
            origin.AbsolutePath != "/" || origin.Query != "" || origin.Fragment != "" || origin.UserInfo != "" ||
            !string.Equals(origin.Host, RelyingPartyId, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Console Origin must be HTTPS and its host must equal RelyingPartyId.");
        if (IdleMinutes is < 1 or > 60 || AbsoluteMinutes < IdleMinutes || AbsoluteMinutes > 1440 || StepUpMinutes is < 1 or > 10)
            throw new InvalidOperationException("Invalid session policy bounds.");
        if (EmergencyLogin && EmergencyAllowedAddresses.Length == 0)
            throw new InvalidOperationException("Emergency login requires explicit source addresses.");
        foreach (var address in EmergencyAllowedAddresses)
            if (!System.Net.IPAddress.TryParse(address, out _)) throw new InvalidOperationException("Invalid emergency address.");
    }
}
