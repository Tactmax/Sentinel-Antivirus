using System.IO;
using System.Windows;
using System.Windows.Threading;
using Sentinel.Services;

namespace Sentinel;

public partial class App : Application
{
    public static AppServices Services { get; set; } = null!;

    public sealed class AppServices
    {
        public required SettingsService Settings { get; init; }
        public required HistoryService History { get; init; }
        public required QuarantineService Quarantine { get; init; }
        public required ClamAvLocator Locator { get; init; }
        public required ClamAvScanner Scanner { get; init; }
        public required EngineInstaller EngineInstaller { get; init; }
        public required SignatureService Signatures { get; init; }
        public required ClamDaemon Daemon { get; init; }
    }

    /// <summary>
    /// Builds the service container. Shared by normal startup and by the UI smoke
    /// test, so the test exercises the same wiring the real app uses.
    /// </summary>
    public static AppServices CreateServices()
    {
        AppPaths.EnsureDirectories();

        var settingsService = new SettingsService();
        settingsService.Load();
        var historyService = new HistoryService();
        historyService.Load(settingsService.Settings.HistoryLimit);

        return new AppServices
        {
            Settings = settingsService,
            History = historyService,
            Quarantine = new QuarantineService(),
            Locator = new ClamAvLocator(),
            Scanner = new ClamAvScanner(),
            EngineInstaller = new EngineInstaller(),
            Signatures = new SignatureService(),
            Daemon = new ClamDaemon()
        };
    }

    private void Application_Startup(object sender, StartupEventArgs e)
    {
        Services = CreateServices();

        DispatcherUnhandledException += OnDispatcherUnhandledException;
        MainWindow = new MainWindow();
        MainWindow.Show();

        StartBackgroundEngine();
    }

    /// <summary>
    /// Starts ClamAV's daemon so the signature database is loaded once instead of on
    /// every scan. It takes a while to come up, so it runs in the background and the
    /// app falls back to a one-off clamscan until it is ready.
    /// </summary>
    public void StartBackgroundEngine()
    {
        if (!Services.Settings.Settings.UseBackgroundEngine) return;

        ClamAvEngineInfo? engine = Services.Locator.Find(Services.Settings.Settings);
        if (engine is null) return;

        string? engineDir = Path.GetDirectoryName(engine.ClamScanPath);
        if (engineDir is null) return;
        string clamd = Path.Combine(engineDir, "clamd.exe");
        if (!File.Exists(clamd)) return;

        try
        {
            Services.Daemon.Start(clamd, engine.DatabaseDirectory ?? AppPaths.ManagedClamDatabase, AppPaths.LogsDir);
        }
        catch
        {
            // The daemon is an optimisation; a failure just means slower scans.
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try { Services?.Daemon?.Dispose(); } catch { }
        base.OnExit(e);
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        try
        {
            string log = Path.Combine(AppPaths.LogsDir, "sentinel-error.log");
            Directory.CreateDirectory(AppPaths.LogsDir);
            File.AppendAllText(log,
                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {e.Exception}\n\n");
        }
        catch
        {
            // Ignore logging failures.
        }

        MessageBox.Show(
            $"Sentinel hit an unexpected error:\n\n{e.Exception.Message}\n\n" +
            "The error was written to the log folder. You can keep using the app; restart it if screens misbehave.",
            "Unexpected error", MessageBoxButton.OK, MessageBoxImage.Warning);
        e.Handled = true;
    }
}
