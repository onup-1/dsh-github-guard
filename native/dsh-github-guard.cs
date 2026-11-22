// dsh-github-guard native helper.
//
//   dsh-github-guard.exe detect   non-elevated: watches the TCP table and prints
//                                 "EVENT <ip> <unixms>" whenever GitHub traffic appears
//   dsh-github-guard.exe serve    elevated (SYSTEM): named-pipe server that rewrites
//                                 the hosts pins on request
//
// The TLS probing lives in the DSH plugin (Node/OpenSSL), because Schannel on this
// machine cannot complete any handshake (SEC_E_NO_CREDENTIALS). This exe therefore
// stays tiny: it only reads the TCP table and edits the hosts file.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

static class GitHubGuardNative
{
    const string PipeName = "dsh-github-guard";
    const string MarkerLine = "# dsh-github-guard: pinned edge";
    // Left behind by the earlier PowerShell-only guard; dropped on the next rewrite.
    const string LegacyMarkerLine = "# dsh-message-edit: pinned GitHub edge";
    const string HostsPath = @"C:\Windows\System32\drivers\etc\hosts";
    const string LogPath = @"C:\ProgramData\DSHGuard\dsh-github-guard.log";

    static readonly string[] PinnedHosts = { "github.com", "www.github.com", "gist.github.com" };

    static readonly string[] Candidates = {
        "20.29.134.23", "140.82.114.3", "20.175.192.147", "20.217.135.5", "20.207.73.82",
        "140.82.112.3", "140.82.113.3", "140.82.116.3", "140.82.121.3", "20.27.177.113",
        "57.155.223.240", "20.6.7.17", "20.200.245.247", "4.237.22.38", "20.205.243.166",
        "20.205.243.168", "20.201.28.151", "20.26.156.215", "20.248.137.48", "20.233.83.145",
        "20.199.39.232", "4.208.26.197", "20.10.167.104", "20.44.10.50", "20.112.250.133",
        "20.50.68.99", "20.3.94.102", "20.85.128.180", "20.26.4.66", "20.96.76.66",
        "40.71.233.224", "20.99.184.214", "20.97.60.58", "20.115.5.5", "20.76.103.246",
        "20.207.73.83", "20.199.39.233", "20.26.156.216", "20.233.83.146", "4.228.31.149",
    };

    static readonly object LogLock = new object();

    static string HostsFile()
    {
        string overridden = Environment.GetEnvironmentVariable("DSH_GUARD_HOSTS");
        return string.IsNullOrEmpty(overridden) ? HostsPath : overridden;
    }

    static void Log(string line)
    {
        string stamp = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fff") + " " + line + Environment.NewLine;
        string[] targets = {
            Environment.GetEnvironmentVariable("DSH_GUARD_LOG"),
            LogPath,
            Path.Combine(Path.GetTempPath(), "DSHGuard", "dsh-github-guard.log"),
        };
        foreach (string target in targets)
        {
            if (string.IsNullOrEmpty(target)) continue;
            try
            {
                string dir = Path.GetDirectoryName(target);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                lock (LogLock) { File.AppendAllText(target, stamp, Encoding.UTF8); }
                return;
            }
            catch { }
        }
    }

    static int Main(string[] args)
    {
        string mode = args.Length > 0 ? args[0] : "detect";
        if (mode == "serve") { Serve(); return 0; }
        if (mode == "detect") { Detect(); return 0; }
        if (mode == "pin")
        {
            string applied;
            string error;
            bool ok = ApplyPin(args.Length > 1 ? args[1] : string.Empty, out applied, out error);
            Console.WriteLine(ok ? "OK " + applied : "ERR " + error);
            return ok ? 0 : 1;
        }
        Console.Error.WriteLine("usage: dsh-github-guard.exe detect|serve|pin <ip>");
        return 2;
    }

    // ---------------------------------------------------------------- detect

    static void Detect()
    {
        bool created;
        var mutex = new Mutex(true, "Local\\DSHGitHubGuardDetect", out created);
        GC.KeepAlive(mutex);
        if (!created) { Log("detect: another detector is already running"); return; }

        Log("detect: watching for GitHub traffic");
        var known = new HashSet<string>(Candidates, StringComparer.Ordinal);
        DateTime lastTrigger = DateTime.MinValue;

        while (true)
        {
            try
            {
                string pin = CurrentPin();
                if (pin != null) known.Add(pin);

                if ((DateTime.UtcNow - lastTrigger).TotalSeconds >= 60)
                {
                    string hit = null;
                    foreach (string address in RemoteEndpoints())
                    {
                        if (known.Contains(address)) { hit = address; break; }
                    }
                    if (hit != null)
                    {
                        lastTrigger = DateTime.UtcNow;
                        Console.WriteLine("EVENT " + hit + " " + DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
                        Console.Out.Flush();
                        Log("detect: github traffic from " + hit);
                    }
                }
            }
            catch (Exception error)
            {
                Log("detect loop error: " + error.GetType().Name + ": " + error.Message);
            }
            Thread.Sleep(1000);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, uint reserved);

    static List<string> RemoteEndpoints()
    {
        var result = new List<string>();
        int size = 0;
        const int TcpTableOwnerPidAll = 5;
        const int AfInet = 2;
        GetExtendedTcpTable(IntPtr.Zero, ref size, true, AfInet, TcpTableOwnerPidAll, 0);
        if (size == 0) return result;
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buffer, ref size, true, AfInet, TcpTableOwnerPidAll, 0) != 0) return result;
            int rows = Marshal.ReadInt32(buffer);
            IntPtr rowPtr = buffer + 4;
            int rowSize = Marshal.SizeOf(typeof(MibTcpRowOwnerPid));
            for (int i = 0; i < rows; i++)
            {
                var row = (MibTcpRowOwnerPid)Marshal.PtrToStructure(rowPtr + i * rowSize, typeof(MibTcpRowOwnerPid));
                int port = (int)(row.RemotePort & 0xFFFF);
                port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF);
                if (port != 443) continue;
                // 3 = SYN_SENT, 4 = SYN_RECV, 5 = ESTABLISHED. TIME_WAIT lingers for
                // minutes and would make the detector chase its own probes.
                if (row.State != 3 && row.State != 4 && row.State != 5) continue;
                result.Add(new IPAddress(row.RemoteAddr).ToString());
            }
            return result;
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    static string CurrentPin()
    {
        try
        {
            foreach (string raw in File.ReadAllLines(HostsFile()))
            {
                string[] parts = raw.Trim().Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2 && parts[1] == "github.com") return parts[0];
            }
        }
        catch { }
        return null;
    }

    // ---------------------------------------------------------------- serve

    static int GuardPort()
    {
        string raw = Environment.GetEnvironmentVariable("DSH_GUARD_PORT");
        int port;
        if (!string.IsNullOrEmpty(raw) && int.TryParse(raw, out port) && port > 0 && port < 65536) return port;
        return 8898;
    }

    static string GuardToken()
    {
        string env = Environment.GetEnvironmentVariable("DSH_GUARD_TOKEN");
        if (!string.IsNullOrEmpty(env)) return env;
        foreach (string candidate in new[] { @"C:\ProgramData\DSHGuard\token.txt", Path.Combine(Path.GetTempPath(), "DSHGuard", "token.txt") })
        {
            try { if (File.Exists(candidate)) return File.ReadAllText(candidate).Trim(); }
            catch { }
        }
        return string.Empty;
    }

    static void Serve()
    {
        bool created;
        var mutex = new Mutex(true, "Local\\DSHGitHubGuardServe", out created);
        GC.KeepAlive(mutex);
        if (!created) { Log("serve: another helper is already serving"); return; }

        int port = GuardPort();
        string token = GuardToken();
        var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, port);
        try { listener.Start(); }
        catch (Exception error)
        {
            Log("serve: cannot listen on 127.0.0.1:" + port + " - " + error.Message);
            return;
        }
        Log("serve: helper ready on 127.0.0.1:" + port + (token.Length == 0 ? " (no token required)" : " (token required)"));

        while (true)
        {
            try
            {
                using (var client = listener.AcceptTcpClient())
                {
                    client.ReceiveTimeout = 15000;
                    using (var stream = client.GetStream())
                    using (var reader = new StreamReader(stream, Encoding.UTF8))
                    using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
                    {
                        writer.AutoFlush = true;
                        string first = reader.ReadLine();
                        if (first == null) continue;
                        string command = first.Trim();
                        string reply = HandleAuth(command, token);
                        writer.WriteLine(reply);
                        if (reply.StartsWith("ERR", StringComparison.Ordinal)) continue;
                        if (reply == "BYE") { listener.Stop(); return; }
                        string next;
                        while ((next = reader.ReadLine()) != null)
                        {
                            string answer = Handle(next.Trim());
                            writer.WriteLine(answer);
                            if (answer == "BYE") { listener.Stop(); return; }
                        }
                    }
                }
            }
            catch (Exception error)
            {
                Log("serve: " + error.GetType().Name + ": " + error.Message);
                Thread.Sleep(300);
            }
        }
    }

    static string HandleAuth(string line, string expected)
    {
        if (string.Equals(line, "PING", StringComparison.OrdinalIgnoreCase)) return "PONG";
        if (expected.Length > 0)
        {
            string prefix = "AUTH ";
            if (!line.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                Log("serve: rejected command without auth");
                return "ERR auth required";
            }
            if (!string.Equals(line.Substring(prefix.Length).Trim(), expected, StringComparison.Ordinal))
            {
                Log("serve: rejected command with a wrong token");
                return "ERR bad token";
            }
            return "OK authenticated";
        }
        return Handle(line);
    }

    static string Handle(string line)
    {
        if (line.Length == 0) return "ERR empty";
        int space = line.IndexOf(' ');
        string command = (space < 0 ? line : line.Substring(0, space)).ToLowerInvariant();
        string argument = space < 0 ? string.Empty : line.Substring(space + 1).Trim();

        if (command == "ping") return "PONG";
        if (command == "quit") { Log("serve: quit requested"); return "BYE"; }
        if (command == "status")
        {
            string pin = CurrentPin();
            return "PIN " + (pin == null ? "-" : pin);
        }
        if (command == "pin")
        {
            string applied;
            string error;
            bool ok = ApplyPin(argument, out applied, out error);
            Log(ok ? "serve: pinned " + applied : "serve: pin failed: " + error);
            return ok ? "OK " + applied : "ERR " + error;
        }
        return "ERR unknown command '" + command + "'";
    }

    static bool ApplyPin(string value, out string applied, out string error)
    {
        applied = null;
        error = null;
        var ips = new List<string>();
        foreach (string part in (value ?? string.Empty).Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries))
        {
            IPAddress parsed;
            if (IPAddress.TryParse(part, out parsed) && parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                ips.Add(parsed.ToString());
        }
        if (ips.Count == 0) { error = "no valid ipv4 address"; return false; }

        try
        {
            string hostsFile = HostsFile();
            var kept = new List<string>();
            foreach (string raw in File.ReadAllLines(hostsFile))
            {
                string trimmed = raw.Trim();
                if (trimmed.StartsWith(MarkerLine, StringComparison.Ordinal)) continue;
                if (trimmed.StartsWith(LegacyMarkerLine, StringComparison.Ordinal)) continue;
                string[] parts = trimmed.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2 && PinnedHosts.Contains(parts[1].ToLowerInvariant())) continue;
                kept.Add(raw);
            }
            var output = new List<string>(kept);
            while (output.Count > 0 && output[output.Count - 1].Trim().Length == 0) output.RemoveAt(output.Count - 1);
            output.Add(string.Empty);
            output.Add(MarkerLine);
            foreach (string host in PinnedHosts)
                foreach (string ip in ips)
                    output.Add(ip + " " + host);

            File.WriteAllLines(hostsFile, output.ToArray(), Encoding.ASCII);
            FlushDns();
            applied = string.Join(",", ips.ToArray());
            return true;
        }
        catch (Exception failure)
        {
            error = failure.GetType().Name + ": " + failure.Message;
            return false;
        }
    }

    static void FlushDns()
    {
        try
        {
            var info = new ProcessStartInfo("ipconfig", "/flushdns");
            info.UseShellExecute = false;
            info.CreateNoWindow = true;
            info.RedirectStandardOutput = true;
            using (var process = Process.Start(info))
            {
                if (process == null) return;
                process.StandardOutput.ReadToEnd();
                process.WaitForExit(5000);
            }
        }
        catch { }
    }
}
