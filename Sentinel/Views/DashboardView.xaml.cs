using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Win32;
using Sentinel.Models;
using Sentinel.Services;

namespace Sentinel.Views;

/// <summary>
/// The overview screen: engine health, signature freshness, quarantine size, a
/// protection score and recent scans. The scan workspace lives in <see cref="ScanView"/>.
/// </summary>
public partial class DashboardView : UserControl
{
    private const double GaugeDiameter = 150;
    private const double GaugeStroke = 12;

    private ClamAvEngineInfo? _engine;

    public event EventHandler? EngineStatusChanged;

    public ObservableCollection<ScanSession> RecentSessions { get; } = new();
    public event PropertyChangedEventHandler? PropertyChanged;

    public DashboardView()
    {
        InitializeComponent();
        Loaded += (_, _) => RefreshEngineState();
    }

    private void Raise([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    // ---------- engine / cards ----------

    public void RefreshEngineState()
    {
        _engine = App.Services.Locator.Find(App.Services.Settings.Settings);

        bool engineOk = _engine is not null;
        int ageDays = SignatureService.SignatureAgeDays(_engine?.SignatureDateUtc, _engine?.DatabaseDirectory);
        bool defsOk = engineOk && HasAnySignatureFile(_engine!.DatabaseDirectory);

        // --- Scanner row ---
        ScannerStatusChip.Visibility = Visibility.Visible;
        EngineActionPanel.Visibility = engineOk ? Visibility.Collapsed : Visibility.Visible;
        if (engineOk)
        {
            var daemon = App.Services.Daemon;
            string engineState = daemon.IsReady
                ? "background engine ready"
                : daemon.IsRunning ? "background engine warming up" : "one scan per engine start";
            ScannerRowDetail.Text = $"ClamAV {_engine!.EngineVersion ?? "?"} · {engineState}";
            ScannerRowStatus.Text = "Ready";
            ScannerRowStatus.Foreground = FindResource("AccentBrush") as Brush;
            ScannerDot.Fill = FindResource("AccentBrush") as Brush;
        }
        else
        {
            ScannerRowDetail.Text = "Install the ClamAV engine to start scanning";
            ScannerRowStatus.Text = "Not installed";
            ScannerRowStatus.Foreground = FindResource("DangerBrush") as Brush;
            ScannerDot.Fill = FindResource("DangerBrush") as Brush;
        }

        // --- Definitions row ---
        bool defsFresh = defsOk && ageDays >= 0 && ageDays <= App.Services.Settings.Settings.DefinitionsWarnDays;
        bool showDefsButton = engineOk && !defsFresh;
        UpdateDefsRowButton.Visibility = showDefsButton ? Visibility.Visible : Visibility.Collapsed;
        UpdateDefsRowButton.IsEnabled = engineOk;
        DefsStatusChip.Visibility = showDefsButton ? Visibility.Collapsed : Visibility.Visible;
        DefsStatusChip.Background = (Brush)FindResource(!engineOk ? "InputBrush" : "SelectionBrush");

        if (!engineOk)
        {
            DefsRowDetail.Text = "Waiting for the ClamAV engine";
            DefsRowStatus.Text = "Waiting";
            DefsRowStatus.Foreground = FindResource("MutedBrush") as Brush;
            DefsDot.Fill = FindResource("MutedBrush") as Brush;
        }
        else if (!defsOk)
        {
            DefsRowDetail.Text = "Not downloaded — update before scanning";
            DefsRowStatus.Text = "Missing";
            DefsRowStatus.Foreground = FindResource("WarningBrush") as Brush;
            DefsDot.Fill = FindResource("WarningBrush") as Brush;
        }
        else if (!defsFresh)
        {
            DefsRowDetail.Text = $"{ageDays} days old — an update is recommended";
            DefsRowStatus.Text = "Outdated";
            DefsRowStatus.Foreground = FindResource("WarningBrush") as Brush;
            DefsDot.Fill = FindResource("WarningBrush") as Brush;
        }
        else
        {
            DefsRowDetail.Text = _engine!.SignatureDateUtc is DateTime d
                ? $"Up to date · signatures from {d.ToLocalTime():yyyy-MM-dd}"
                : "Up to date";
            DefsRowStatus.Text = "Up to date";
            DefsRowStatus.Foreground = FindResource("AccentBrush") as Brush;
            DefsDot.Fill = FindResource("AccentBrush") as Brush;
        }

        RefreshQuarantineCount();
        RefreshRecentActivity();
        UpdateProtectionScore(engineOk, defsOk, ageDays);
    }

    /// <summary>Scores the scanner out of 100 and paints the gauge.</summary>
    private void UpdateProtectionScore(bool engineOk, bool defsOk, int ageDays)
    {
        int score = 0;
        if (engineOk) score += 40;

        if (defsOk)
        {
            score += ageDays >= 0 && ageDays <= App.Services.Settings.Settings.DefinitionsWarnDays ? 40 : 20;
        }

        bool quarantineOk = true;
        try { _ = App.Services.Quarantine.GetAll(); }
        catch { quarantineOk = false; }
        if (quarantineOk) score += 20;

        ScoreValue.Text = score + "%";
        ScoreLabel.Text = score switch
        {
            >= 100 => "Excellent",
            >= 75 => "Good",
            >= 50 => "Needs attention",
            _ => "Action required"
        };
        ScoreArc.Stroke = FindResource(score >= 75 ? "ScoreGradientBrush" : "ScoreWarnBrush") as Brush;

        double circumference = Math.PI * GaugeDiameter;
        double length = Math.Max(0, (score / 100.0) * circumference - GaugeStroke);
        ScoreArc.StrokeDashArray = new DoubleCollection(new[] { length, circumference });

        BreakEngine.Text = engineOk ? "Yes" : "Missing";
        BreakDefs.Text = defsOk ? (ageDays >= 0 ? $"{ageDays} day(s) old" : "Installed") : "Missing";
        BreakQuarantine.Text = quarantineOk ? "Yes" : "Unavailable";
    }

    public void RefreshQuarantineCount()
    {
        try
        {
            int count = App.Services.Quarantine.GetAll().Count;
            QuarantineRowDetail.Text = count == 0
                ? "Empty · encrypted at rest"
                : $"{count} item{(count == 1 ? "" : "s")} · encrypted at rest";
        }
        catch
        {
            QuarantineRowDetail.Text = "Unavailable — the quarantine key could not be read";
        }
    }

    public void RefreshRecentActivity()
    {
        RecentSessions.Clear();
        foreach (ScanSession session in App.Services.History.Sessions.Take(5)) RecentSessions.Add(session);
        RecentEmptyHint.Visibility = RecentSessions.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private static bool HasAnySignatureFile(string? dbDir)
    {
        if (string.IsNullOrEmpty(dbDir) || !Directory.Exists(dbDir)) return false;
        try
        {
            return Directory.EnumerateFiles(dbDir, "*.cvd").Any() ||
                   Directory.EnumerateFiles(dbDir, "*.cld").Any();
        }
        catch
        {
            return false;
        }
    }

    // ---------- engine install ----------

    private void InstallEngine_Click(object sender, RoutedEventArgs e) => _ = InstallEngineFromSettingsAsync();

    public async Task InstallEngineFromSettingsAsync()
    {
        var confirm = MessageBox.Show(
            $"Sentinel will download the official ClamAV {EngineInstaller.ClamAvVersion} portable package from the Cisco Talos GitHub release " +
            $"(about 200 MB), verify its SHA-256 digest, and install it for your Windows account.\n\n" +
            "No administrator rights are required. Continue?",
            "Install ClamAV engine", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (confirm != MessageBoxResult.Yes) return;

        InstallEngineButton.IsEnabled = false;
        EngineActionPanel.Visibility = Visibility.Visible;
        EngineMissingPanel.Visibility = Visibility.Collapsed;
        InstallPanel.Visibility = Visibility.Visible;
        EngineInstallProgress.Visibility = Visibility.Visible;
        EngineInstallProgress.IsIndeterminate = false;
        try
        {
            var progress = new Progress<EngineInstallProgress>(p =>
            {
                EngineInstallText.Text = p.Percent is double pct
                    ? $"{p.Stage} ({pct:0}%)"
                    : p.Stage;
                if (p.Percent is double v)
                {
                    EngineInstallProgress.IsIndeterminate = false;
                    EngineInstallProgress.Value = v;
                }
                else
                {
                    EngineInstallProgress.IsIndeterminate = true;
                }
            });

            EngineInstallResult result = await App.Services.EngineInstaller.InstallAsync(progress, CancellationToken.None);

            App.Services.Settings.Settings.EnginePath = result.ClamScanPath;
            App.Services.Settings.Settings.FreshClamPath = result.FreshClamPath;
            App.Services.Settings.Settings.DatabaseDirectory = result.DatabaseDirectory;
            App.Services.Settings.Save();

            EngineInstallText.Text = "ClamAV installed.";
            RefreshEngineState();
            EngineStatusChanged?.Invoke(this, EventArgs.Empty);
            (Application.Current as Sentinel.App)?.StartBackgroundEngine();

            var updateNow = MessageBox.Show(
                "ClamAV is installed, but it has no virus signatures yet.\n\nDownload the latest signatures now? (Usually 200–400 MB on first run.)",
                "Download signatures", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (updateNow == MessageBoxResult.Yes)
            {
                await UpdateSignaturesAsync();
            }
            else
            {
                MessageBox.Show("You can download signatures any time with “Update definitions” on the dashboard or in Settings.",
                    "Deferred", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"ClamAV could not be installed:\n\n{ex.Message}", "Engine install failed",
                MessageBoxButton.OK, MessageBoxImage.Error);
            EngineInstallText.Text = "Install failed.";
        }
        finally
        {
            InstallEngineButton.IsEnabled = true;
            EngineMissingPanel.Visibility = Visibility.Visible;
            InstallPanel.Visibility = Visibility.Collapsed;
            EngineInstallProgress.Visibility = Visibility.Collapsed;
            EngineInstallProgress.IsIndeterminate = false;
            EngineActionPanel.Visibility = _engine is null ? Visibility.Visible : Visibility.Collapsed;
        }
    }

    private void HaveClamAv_Click(object sender, RoutedEventArgs e)
    {
        var window = Window.GetWindow(this);
        window?.Activate();
        var dialog = new OpenFileDialog
        {
            Title = "Locate clamscan.exe",
            Filter = "ClamAV scanner (clamscan.exe)|clamscan.exe|Executables (*.exe)|*.exe",
            CheckFileExists = true
        };
        if (dialog.ShowDialog(window) != true) return;

        ClamAvEngineInfo? info = App.Services.Locator.TryGetEngineInfo(dialog.FileName, App.Services.Settings.Settings);
        if (info is null)
        {
            MessageBox.Show(
                $"Sentinel could not run \"{dialog.FileName}\" to confirm it is clamscan.exe.\n\n" +
                "Make sure you selected clamscan.exe from an official ClamAV package, and that its DLLs are in the same folder.",
                "Could not verify engine", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        App.Services.Settings.Settings.EnginePath = info.ClamScanPath;
        App.Services.Settings.Save();
        RefreshEngineState();
        EngineStatusChanged?.Invoke(this, EventArgs.Empty);

        if (!HasAnySignatureFile(info.DatabaseDirectory))
        {
            var updateNow = MessageBox.Show(
                $"Found ClamAV {info.EngineVersion}.\n\nNo virus signatures were detected. Download signatures now?",
                "Download signatures", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (updateNow == MessageBoxResult.Yes)
            {
                _ = UpdateSignaturesAsync();
            }
        }
    }

    // ---------- signatures ----------

    private void UpdateDefsRow_Click(object sender, RoutedEventArgs e) => _ = UpdateSignaturesAsync();

    public async Task UpdateSignaturesAsync()
    {
        if (_engine is null)
        {
            MessageBox.Show("Install the ClamAV engine first.", "No engine", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        string? freshclam = _engine.FreshClamPath
            ?? (File.Exists(App.Services.Settings.Settings.FreshClamPath) ? App.Services.Settings.Settings.FreshClamPath : null);
        if (freshclam is null)
        {
            MessageBox.Show(
                "freshclam.exe was not found next to clamscan.exe.\nReinstall the ClamAV engine from Settings to fix this.",
                "freshclam missing", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        string? config = File.Exists(AppPaths.ManagedClamConfig) ? AppPaths.ManagedClamConfig : null;
        try
        {
            SignatureUpdateResult result = await App.Services.Signatures.UpdateAsync(freshclam, config, output: null, CancellationToken.None);
            MessageBox.Show(result.Message, result.Success ? "Definitions" : "Update problem",
                MessageBoxButton.OK, result.Success ? MessageBoxImage.Information : MessageBoxImage.Warning);
            RefreshEngineState();
            EngineStatusChanged?.Invoke(this, EventArgs.Empty);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Signature update failed:\n\n{ex.Message}", "Update error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    // ---------- navigation & quick scans ----------

    private void GoToScan_Click(object sender, RoutedEventArgs e) =>
        (Window.GetWindow(this) as MainWindow)?.Navigate("scan");

    private void GoToQuarantine_Click(object sender, RoutedEventArgs e) =>
        (Window.GetWindow(this) as MainWindow)?.Navigate("quarantine");

    private void ViewHistory_Click(object sender, RoutedEventArgs e) =>
        (Window.GetWindow(this) as MainWindow)?.Navigate("history");

    private async void QuickScan_Click(object sender, RoutedEventArgs e)
    {
        var main = Window.GetWindow(this) as MainWindow;
        if (main is null) return;
        main.Navigate("scan");
        await Task.Yield();
        await main.ScanView.QuickScanAsync();
    }

    private async void FullScan_Click(object sender, RoutedEventArgs e)
    {
        var main = Window.GetWindow(this) as MainWindow;
        if (main is null) return;
        main.Navigate("scan");
        await Task.Yield();
        await main.ScanView.FullScanAsync();
    }

    private void TargetBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) _ = ScanTargetFromBoxAsync();
    }

    private async void ScanTarget_Click(object sender, RoutedEventArgs e) => await ScanTargetFromBoxAsync();

    private async Task ScanTargetFromBoxAsync()
    {
        string target = TargetBox.Text.Trim().Trim('"');
        if (string.IsNullOrEmpty(target))
        {
            var dialog = new OpenFolderDialog { Title = "Choose a folder to scan" };
            if (dialog.ShowDialog() != true) return;
            target = dialog.FolderName;
        }
        var main = Window.GetWindow(this) as MainWindow;
        if (main is null) return;
        main.Navigate("scan");
        await Task.Yield();
        await main.ScanView.SetTargetAndScan(target);
    }

    public Task SetTargetAndScan(string target)
    {
        TargetBox.Text = target;
        var main = Window.GetWindow(this) as MainWindow;
        if (main is null) return Task.CompletedTask;
        main.Navigate("scan");
        return main.ScanView.SetTargetAndScan(target);
    }
}
