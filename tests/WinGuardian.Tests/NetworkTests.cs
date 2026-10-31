using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging.Abstractions;
using WinGuardian.Core;
using WinGuardian.Core.Data;
using WinGuardian.Core.Monitoring;
using WinGuardian.Core.Network;

namespace WinGuardian.Tests;

public class NetworkTests : IDisposable
{
    private readonly string _work = Path.Combine(Path.GetTempPath(), "wg-tests", Guid.NewGuid().ToString("N"));
    private readonly GuardianDatabase _db;
    private readonly NetworkMonitor _monitor;

    public NetworkTests()
    {
        Directory.CreateDirectory(_work);
        _db = new GuardianDatabase(Path.Combine(_work, "net.db"));
        _db.Initialize();
        var events = new EventRecorder(_db, new TrustStore(_db), NullLogger<EventRecorder>.Instance);
        _monitor = new NetworkMonitor(_db, events, NullLogger<NetworkMonitor>.Instance);
    }

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_work, true); } catch (IOException) { }
    }

    [Fact]
    public void Port_is_decoded_from_network_byte_order()
    {
        Assert.Equal(80, SocketTables.Port(0x5000));
        Assert.Equal(443, SocketTables.Port(0xBB01));
        Assert.Equal(49664, SocketTables.Port(0x00C2));
    }

    [Fact]
    public void Own_tcp_listener_and_udp_socket_appear_with_our_pid()
    {
        using var tcp = new TcpListener(IPAddress.Loopback, 0);
        tcp.Start();
        using var udp = new UdpClient(new IPEndPoint(IPAddress.IPv6Loopback, 0));
        var tcpPort = ((IPEndPoint)tcp.LocalEndpoint).Port;
        var udpPort = ((IPEndPoint)udp.Client.LocalEndPoint!).Port;
        var pid = Environment.ProcessId;

        var sockets = SocketTables.Capture();
        Assert.Contains(sockets, s => s.Protocol == "TCP" && s.LocalPort == tcpPort && s.State == "Listen" && s.Pid == pid &&
                                      s.LocalAddress.Equals(IPAddress.Loopback));
        Assert.Contains(sockets, s => s.Protocol == "UDPv6" && s.LocalPort == udpPort && s.Pid == pid);
    }

    [Fact]
    public void Established_connection_shows_both_ends()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var client = new TcpClient();
        client.Connect(IPAddress.Loopback, port);
        using var accepted = listener.AcceptTcpClient();
        var clientPort = ((IPEndPoint)client.Client.LocalEndPoint!).Port;

        var sockets = SocketTables.Capture();
        Assert.Contains(sockets, s => s.Protocol == "TCP" && s.State == "Established" && s.LocalPort == clientPort && s.RemotePort == port);
    }

    [Fact]
    public void Services_are_mapped_to_their_host_process()
    {
        var map = ServiceProcessMap.Capture();
        Assert.Contains(map.Values, list => list.Any(s => s.StartsWith("RpcSs", StringComparison.OrdinalIgnoreCase)));
        var rpcPid = map.First(kv => kv.Value.Any(s => s.StartsWith("RpcSs", StringComparison.OrdinalIgnoreCase))).Key;
        using var host = Process.GetProcessById(rpcPid);
        Assert.Equal("svchost", host.ProcessName, ignoreCase: true);
    }

    [Fact]
    public void Firewall_rule_string_is_parsed()
    {
        var rule = FirewallConfig.Parse("{ABC}", "Local",
            @"v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=8080|RA4=LocalSubnet|App=%SystemDrive%\Tools\srv.exe|Name=My Server|Desc=Test rule|");
        Assert.Equal("Allow", rule.Action);
        Assert.Equal("In", rule.Direction);
        Assert.True(rule.Enabled);
        Assert.True(rule.AllowsInbound);
        Assert.Equal("TCP", rule.Protocol);
        Assert.Equal("8080", rule.LocalPorts);
        Assert.Equal("Private,Public", rule.Profiles);
        Assert.Equal("LocalSubnet", rule.RemoteAddresses);
        Assert.Equal(Environment.ExpandEnvironmentVariables(@"%SystemDrive%\Tools\srv.exe"), rule.Program);
        Assert.Equal("My Server", rule.Name);
        Assert.Equal("Local|{ABC}", rule.Key);
    }

    [Fact]
    public void Rule_diff_reports_added_modified_and_removed()
    {
        const string original = "v2.31|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=23|Name=Telnet|";
        var stored = new Dictionary<string, string>
        {
            ["Local|keep"] = "v2.31|Action=Allow|Active=TRUE|Dir=Out|Name=Keep|",
            ["Local|change"] = original,
            ["Local|gone"] = "v2.31|Action=Allow|Active=TRUE|Dir=Out|Name=Gone|",
        };
        var current = new List<FirewallRule>
        {
            FirewallConfig.Parse("keep", "Local", stored["Local|keep"]),
            FirewallConfig.Parse("change", "Local", original.Replace("Action=Block", "Action=Allow")),
            FirewallConfig.Parse("new", "Local", "v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort=9999|Name=New|"),
        };

        var diff = NetworkMonitor.DiffRules(stored, current);
        Assert.Equal(3, diff.Count);
        Assert.Contains(diff, d => d.Change == ChangeKind.Added && d.Rule.Name == "New");
        Assert.Contains(diff, d => d.Change == ChangeKind.Removed && d.Rule.Name == "Gone");
        var modified = Assert.Single(diff, d => d.Change == ChangeKind.Modified);
        Assert.Equal("Block", modified.Previous!.Action);
        Assert.Equal("Allow", modified.Rule.Action);
    }

    [Fact]
    public void Dynamic_ports_are_grouped_per_program()
    {
        NetworkEndpoint L(int port, string path = @"C:\App\a.exe") =>
            new() { Protocol = "TCP", LocalAddress = "0.0.0.0", LocalPort = port, ProcessName = "a.exe", ProcessPath = path };
        Assert.Equal(NetworkMonitor.ListenerKey(L(50001)), NetworkMonitor.ListenerKey(L(61234)));
        Assert.NotEqual(NetworkMonitor.ListenerKey(L(8080)), NetworkMonitor.ListenerKey(L(8081)));
        Assert.NotEqual(NetworkMonitor.ListenerKey(L(50001)), NetworkMonitor.ListenerKey(L(50001, @"C:\App\b.exe")));
    }

    [Theory]
    [InlineData(true, "Microsoft Windows", false, "0.0.0.0", Severity.Info)]
    [InlineData(false, "Valve Corp.", false, "0.0.0.0", Severity.Low)]
    [InlineData(false, null, false, "0.0.0.0", Severity.Medium)]
    [InlineData(false, null, true, "0.0.0.0", Severity.High)]
    [InlineData(false, null, true, "127.0.0.1", Severity.Medium)]
    public void Listener_severity_follows_signature_location_and_binding(bool microsoft, string? signer, bool userWritable, string address, Severity expected)
    {
        var l = new NetworkEndpoint
        {
            Protocol = "TCP", LocalAddress = address, LocalPort = 8080, ProcessName = "x.exe", ProcessPath = @"C:\x\x.exe",
            SignedByMicrosoft = microsoft, Signer = signer, InUserWritableLocation = userWritable,
        };
        Assert.Equal(expected, NetworkMonitor.ListenerSeverity(l));
    }

    [Fact]
    public void New_listening_port_raises_one_event()
    {
        _monitor.CaptureBaseline();

        // A fixed (non-dynamic) port opened by this unsigned test program after the baseline.
        TcpListener? listener = null;
        for (var port = 31000 + Random.Shared.Next(0, 8000); listener is null; port++)
        {
            try { listener = new TcpListener(IPAddress.Loopback, port); listener.Start(); }
            catch (SocketException) { listener = null; }
        }
        using (listener)
        {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            _monitor.Poll();
            _monitor.Poll(); // must not report the same listener twice

            var e = Assert.Single(_db.GetEvents(null, 100, false), x => x.Category == EventCategory.Network && x.Change == ChangeKind.Added);
            Assert.Contains($"TCP {port}", e.Subject);
            Assert.Equal(Environment.ProcessPath, e.FilePath, ignoreCase: true);
            Assert.Contains("this computer only", e.Details);
            Assert.Equal(Severity.Medium, e.Severity); // unsigned + user folder = High, reduced one step for loopback-only

            var snapshot = _monitor.GetSnapshot();
            var mine = Assert.Single(snapshot.Listeners, l => l.LocalPort == port && l.Protocol == "TCP");
            Assert.Equal(Environment.ProcessId, mine.Pid);
            Assert.NotNull(mine.FirstSeenUtc);
        }
    }

    [Fact]
    public void Reads_real_firewall_configuration()
    {
        var rules = FirewallConfig.ReadRules();
        Assert.NotEmpty(rules);
        Assert.DoesNotContain(rules, r => r.Name.StartsWith("@FirewallAPI.dll", StringComparison.OrdinalIgnoreCase)); // resource names resolved
        var status = FirewallConfig.ReadStatus(rules);
        Assert.Equal(["Domain", "Private", "Public"], status.Profiles.Select(p => p.Name));
    }
}
