using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Sentinel.Services;

/// <summary>
/// Runs ClamAV's <c>clamd</c> daemon so the signature database is loaded once and
/// stays resident in memory.
///
/// This matters a great deal on Windows: <c>clamscan</c> reloads and verifies the
/// whole signature database on every single invocation, which costs over a minute
/// here. A daemon pays that cost once at start-up and then answers each scan in
/// milliseconds, and it scans files in parallel by itself.
/// </summary>
public sealed class ClamDaemon : IDisposable
{
    private const int MaxLineBytes = 8 * 1024;

    private readonly object _gate = new();
    private readonly SemaphoreSlim _scanGate = new(1, 1);

    private Process? _process;
    private TcpClient? _client;
    private NetworkStream? _stream;
    private StreamReader? _reader;
    private StreamWriter? _writer;

    private bool _disposed;

    public bool IsReady { get; private set; }
    public string? LastError { get; private set; }
    public int Port { get; private set; }
    public bool IsRunning => _process is { HasExited: false };

    /// <summary>Raised when the daemon starts loading, and again when it becomes usable.</summary>
    public event EventHandler? StateChanged;

    /// <summary>
    /// Starts the daemon in the background. Returns immediately; the database takes
    /// a while to load, so callers should poll <see cref="IsReady"/>.
    /// </summary>
    public void Start(string clamdPath, string databaseDirectory, string logDirectory, CancellationToken ct = default)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(ClamDaemon));
        if (_process is not null) return;
        if (!File.Exists(clamdPath))
        {
            LastError = "clamd.exe was not found next to clamscan.exe.";
            return;
        }

        try
        {
            Directory.CreateDirectory(logDirectory);
            int port = ReserveFreePort();
            Port = port;

            string configPath = Path.Combine(Path.GetDirectoryName(clamdPath) ?? ".", "sentinel-clamd.conf");
            // No byte-order mark: ClamAV's config parser rejects a BOM.
            File.WriteAllText(configPath, BuildConfig(port, databaseDirectory, logDirectory), new UTF8Encoding(false));

            var startInfo = new ProcessStartInfo
            {
                FileName = clamdPath,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WorkingDirectory = Path.GetDirectoryName(clamdPath) ?? Environment.CurrentDirectory
            };
            startInfo.ArgumentList.Add($"--config-file={configPath}");

            _process = Process.Start(startInfo);
            if (_process is null)
            {
                LastError = "clamd could not be started.";
                return;
            }

            // clamd logs to its own file; swallow the console streams.
            _ = _process.StandardOutput.ReadToEndAsync();
            _ = _process.StandardError.ReadToEndAsync();

            _ = Task.Run(() => WaitUntilReadyAsync(ct), CancellationToken.None);
            StateChanged?.Invoke(this, EventArgs.Empty);
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
            _process = null;
        }
    }

    private async Task WaitUntilReadyAsync(CancellationToken ct)
    {
        try
        {
            // Loading and verifying the signature database is the slow part.
            DateTime deadline = DateTime.UtcNow.AddMinutes(5);
            while (DateTime.UtcNow < deadline && !ct.IsCancellationRequested)
            {
                if (_process is { HasExited: true })
                {
                    LastError = "clamd exited while loading the signature database.";
                    return;
                }
                if (TryConnect())
                {
                    IsReady = true;
                    StateChanged?.Invoke(this, EventArgs.Empty);
                    return;
                }
                await Task.Delay(400, ct).ConfigureAwait(false);
            }
            if (!IsReady) LastError ??= "clamd did not become ready in time.";
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
        }
    }

    private bool TryConnect()
    {
        try
        {
            var client = new TcpClient();
            client.NoDelay = true;
            client.Connect(IPAddress.Loopback, Port);
            var stream = client.GetStream();
            var writer = new StreamWriter(stream, new UTF8Encoding(false), MaxLineBytes) { AutoFlush = true, NewLine = "\n" };
            var reader = new StreamReader(stream, new UTF8Encoding(false), false, MaxLineBytes, leaveOpen: true);

            _client = client;
            _stream = stream;
            _writer = writer;
            _reader = reader;
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Asks the daemon to scan one file. Returns the threat name, or null when the
    /// file is clean. <paramref name="error"/> is set when the daemon could not
    /// scan the file at all.
    /// </summary>
    public string? ScanFile(string path, out string? error)
    {
        error = null;
        if (!IsReady) { error = "The scan engine is still starting."; return null; }

        _scanGate.Wait();
        try
        {
            lock (_gate)
            {
                if (_writer is null || _reader is null)
                {
                    error = "The scan engine connection was lost.";
                    return null;
                }
                _writer.Write($"zSCAN {path}\0");
                while (true)
                {
                    string? raw = _reader.ReadLine();
                    if (raw is null)
                    {
                        error = "The scan engine connection was lost.";
                        IsReady = false;
                        return null;
                    }
                    // clamd pads its replies with a trailing space.
                    string line = raw.Trim();
                    if (line.Length == 0) continue;
                    if (line == "zEND") return null;
                    if (line.EndsWith(" FOUND", StringComparison.Ordinal))
                    {
                        (_, string threat) = ClamAvScanner.SplitFoundLine(line);
                        return threat;
                    }
                    if (!line.EndsWith(": OK", StringComparison.Ordinal))
                    {
                        // e.g. "path: Can't open file" - report but do not treat as a detection.
                        error = line;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            error = ex.Message;
            IsReady = false;
            return null;
        }
        finally
        {
            _scanGate.Release();
        }
    }

    private static int ReserveFreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static string BuildConfig(int port, string databaseDirectory, string logDirectory) =>
        $"""
        LogFile "{logDirectory.Replace("\\", "\\\\")}\\clamd.log"
        LogTime yes
        LogVerbose no
        PidFile "{Path.GetTempPath().Replace("\\", "\\\\")}sentinel-clamd.pid"
        DatabaseDirectory "{databaseDirectory.Replace("\\", "\\\\")}"
        TCPSocket {port}
        TCPAddr 127.0.0.1
        MaxThreads 8
        MaxDirectoryRecursion 30
        ScanArchive yes
        Foreground yes
        """;

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        try { _reader?.Dispose(); } catch { }
        try { _writer?.Dispose(); } catch { }
        try { _stream?.Dispose(); } catch { }
        try { _client?.Dispose(); } catch { }

        if (_process is { HasExited: false })
        {
            try { _process.Kill(entireProcessTree: true); } catch { }
        }
        try { _process?.Dispose(); } catch { }
        _scanGate.Dispose();
    }
}
