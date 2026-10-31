using System.Net;
using System.Runtime.InteropServices;

namespace WinGuardian.Core.Network;

public sealed record SocketEntry(string Protocol, IPAddress LocalAddress, int LocalPort, IPAddress? RemoteAddress, int? RemotePort,
    string? State, int Pid);

/// <summary>
/// Reads the kernel's TCP and UDP endpoint tables (IPv4 and IPv6) with owning process IDs, via
/// GetExtendedTcpTable / GetExtendedUdpTable — the same data netstat -ano shows. Read-only and cheap.
/// </summary>
public static class SocketTables
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int TcpTableOwnerPidAll = 5;
    private const int UdpTableOwnerPid = 1;
    private const int ErrorInsufficientBuffer = 122;

    private static readonly string[] TcpStates =
        ["", "Closed", "Listen", "SynSent", "SynReceived", "Established", "FinWait1", "FinWait2", "CloseWait", "Closing", "LastAck", "TimeWait", "DeleteTcb"];

    public static List<SocketEntry> Capture()
    {
        var result = new List<SocketEntry>();
        ReadTcp(AfInet, result);
        ReadTcp(AfInet6, result);
        ReadUdp(AfInet, result);
        ReadUdp(AfInet6, result);
        return result;
    }

    /// <summary>Port fields hold the port in network byte order in their low 16 bits.</summary>
    public static int Port(uint raw) => (int)(((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF));

    private static void ReadTcp(int family, List<SocketEntry> result)
    {
        WithTable(NativeGetExtendedTcpTable, family, TcpTableOwnerPidAll, table =>
        {
            var count = Marshal.ReadInt32(table);
            var row = table + 4;
            var proto = family == AfInet ? "TCP" : "TCPv6";
            for (var i = 0; i < count; i++)
            {
                if (family == AfInet)
                {
                    // MIB_TCPROW_OWNER_PID: state, localAddr, localPort, remoteAddr, remotePort, pid (6 DWORDs)
                    var state = (uint)Marshal.ReadInt32(row);
                    var local = new IPAddress((uint)Marshal.ReadInt32(row, 4));
                    var localPort = Port((uint)Marshal.ReadInt32(row, 8));
                    var remote = new IPAddress((uint)Marshal.ReadInt32(row, 12));
                    var remotePort = Port((uint)Marshal.ReadInt32(row, 16));
                    var pid = Marshal.ReadInt32(row, 20);
                    result.Add(Tcp(proto, local, localPort, remote, remotePort, state, pid));
                    row += 24;
                }
                else
                {
                    // MIB_TCP6ROW_OWNER_PID: localAddr[16], localScope, localPort, remoteAddr[16], remoteScope, remotePort, state, pid
                    var local = new IPAddress(Bytes(row, 16), (uint)Marshal.ReadInt32(row, 16));
                    var localPort = Port((uint)Marshal.ReadInt32(row, 20));
                    var remote = new IPAddress(Bytes(row + 24, 16), (uint)Marshal.ReadInt32(row, 40));
                    var remotePort = Port((uint)Marshal.ReadInt32(row, 44));
                    var state = (uint)Marshal.ReadInt32(row, 48);
                    var pid = Marshal.ReadInt32(row, 52);
                    result.Add(Tcp(proto, local, localPort, remote, remotePort, state, pid));
                    row += 56;
                }
            }
        });
    }

    private static SocketEntry Tcp(string proto, IPAddress local, int localPort, IPAddress remote, int remotePort, uint state, int pid)
    {
        var stateName = state < TcpStates.Length ? TcpStates[state] : $"State{state}";
        var listening = stateName == "Listen";
        return new SocketEntry(proto, local, localPort, listening ? null : remote, listening ? null : remotePort, stateName, pid);
    }

    private static void ReadUdp(int family, List<SocketEntry> result)
    {
        WithTable(NativeGetExtendedUdpTable, family, UdpTableOwnerPid, table =>
        {
            var count = Marshal.ReadInt32(table);
            var row = table + 4;
            for (var i = 0; i < count; i++)
            {
                if (family == AfInet)
                {
                    // MIB_UDPROW_OWNER_PID: localAddr, localPort, pid
                    result.Add(new SocketEntry("UDP", new IPAddress((uint)Marshal.ReadInt32(row)), Port((uint)Marshal.ReadInt32(row, 4)),
                        null, null, null, Marshal.ReadInt32(row, 8)));
                    row += 12;
                }
                else
                {
                    // MIB_UDP6ROW_OWNER_PID: localAddr[16], localScope, localPort, pid
                    result.Add(new SocketEntry("UDPv6", new IPAddress(Bytes(row, 16), (uint)Marshal.ReadInt32(row, 16)),
                        Port((uint)Marshal.ReadInt32(row, 20)), null, null, null, Marshal.ReadInt32(row, 24)));
                    row += 28;
                }
            }
        });
    }

    private delegate int TableFunction(IntPtr table, ref int size, bool order, int family, int tableClass, uint reserved);

    /// <summary>Calls the API with a growing buffer (the table can grow between the size query and the read).</summary>
    private static void WithTable(TableFunction read, int family, int tableClass, Action<IntPtr> parse)
    {
        var size = 64 * 1024;
        for (var attempt = 0; attempt < 5; attempt++)
        {
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                var rc = read(buffer, ref size, false, family, tableClass, 0);
                if (rc == 0)
                {
                    parse(buffer);
                    return;
                }
                if (rc != ErrorInsufficientBuffer) return;
                size += 16 * 1024;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }
    private static byte[] Bytes(IntPtr p, int count)
    {
        var bytes = new byte[count];
        Marshal.Copy(p, bytes, 0, count);
        return bytes;
    }

    [DllImport("iphlpapi.dll", EntryPoint = "GetExtendedTcpTable")]
    private static extern int NativeGetExtendedTcpTable(IntPtr table, ref int size, bool order, int family, int tableClass, uint reserved);

    [DllImport("iphlpapi.dll", EntryPoint = "GetExtendedUdpTable")]
    private static extern int NativeGetExtendedUdpTable(IntPtr table, ref int size, bool order, int family, int tableClass, uint reserved);
}
