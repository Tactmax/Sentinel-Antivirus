using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using Sentinel.Services;

namespace Sentinel.Views;

public partial class SettingsView : UserControl
{
    private bool _reloading;

    public SettingsView()
    {
        InitializeComponent();
        Loaded += (_, _) => Reload();
    }

    public void Reload()
    {
        _reloading = true;
        try
        {
            var settings = App.Services.Settings.Settings;
            var engine = App.Services.Locator.Find(settings);
            EnginePathBox.Text = engine?.ClamScanPath ?? settings.EnginePath;
            ScanArchivesBox.IsChecked = settings.ScanArchives;
            BackgroundEngineBox.IsChecked = settings.UseBackgroundEngine;
            ParallelScanBox.IsChecked = settings.ParallelScan;
            ParallelWorkersBox.Text = settings.ParallelWorkers > 0 ? settings.ParallelWorkers.ToString() : "";
            MaxFileSizeBox.Text = settings.MaxFileSizeMb > 0 ? settings.MaxFileSizeMb.ToString() : "";
            MaxScanSizeBox.Text = settings.MaxScanSizeMb > 0 ? settings.MaxScanSizeMb.ToString() : "";
            MaxScanTimeBox.Text = settings.MaxScanTimeMs > 0 ? settings.MaxScanTimeMs.ToString() : "";
            DataPathText.Text = AppPaths.Root;

            EngineStatusLabel.Text = engine is null
                ? "No engine configured."
                : $"ClamAV {engine.EngineVersion} · signatures {(engine.SignatureDateUtc is DateTime d ? d.ToLocalTime().ToString("yyyy-MM-dd") : "unknown")}" +
                  (engine.FreshClamPath is null ? " · freshclam not found" : "");
        }
        finally
        {
            _reloading = false;
        }
    }

    private void BrowseEngine_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Locate clamscan.exe",
            Filter = "ClamAV scanner (clamscan.exe)|clamscan.exe|Executables (*.exe)|*.exe",
            CheckFileExists = true
        };
        if (dialog.ShowDialog() == true) EnginePathBox.Text = dialog.FileName;
    }

    private void ValidateEngine_Click(object sender, RoutedEventArgs e)
    {
        string path = EnginePathBox.Text.Trim().Trim('"');
        if (string.IsNullOrEmpty(path) || !File.Exists(path))
        {
            MessageBox.Show("That file does not exist.", "Invalid engine path", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        ClamAvEngineInfo? info = App.Services.Locator.TryGetEngineInfo(path, App.Services.Settings.Settings);
        if (info is null)
        {
            MessageBox.Show(
                $"\"{path}\" could not be started as clamscan.exe.\n\nCheck that clamscan.exe and the DLLs from the same ClamAV package are in that folder.",
                "Engine check failed", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        App.Services.Settings.Settings.EnginePath = info.ClamScanPath;
        if (info.FreshClamPath is not null) App.Services.Settings.Settings.FreshClamPath = info.FreshClamPath;
        if (info.DatabaseDirectory is not null) App.Services.Settings.Settings.DatabaseDirectory = info.DatabaseDirectory;
        App.Services.Settings.Save();
        Reload();
        (Window.GetWindow(this) as MainWindow)?.RefreshSidebarEngineText();
        MessageBox.Show($"Engine verified:\n{info.VersionLine}", "Engine OK", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private async void InstallEngine_Click(object sender, RoutedEventArgs e)
    {
        var dashboard = (Window.GetWindow(this) as MainWindow)?.DashboardView;
        if (dashboard is null) return;
        (Window.GetWindow(this) as MainWindow)?.Navigate("dashboard");
        await Task.Yield();
        _ = dashboard.InstallEngineFromSettingsAsync();
    }

    private async void UpdateSignatures_Click(object sender, RoutedEventArgs e)
    {
        var dashboard = (Window.GetWindow(this) as MainWindow)?.DashboardView;
        if (dashboard is null) return;
        (Window.GetWindow(this) as MainWindow)?.Navigate("dashboard");
        await Task.Yield();
        await dashboard.UpdateSignaturesAsync();
    }

    private void Option_Changed(object sender, RoutedEventArgs e)
    {
        if (_reloading) return;
        var settings = App.Services.Settings.Settings;
        settings.ScanArchives = ScanArchivesBox.IsChecked == true;
        settings.ParallelScan = ParallelScanBox.IsChecked == true;

        bool wantBackground = BackgroundEngineBox.IsChecked == true;
        if (wantBackground != settings.UseBackgroundEngine)
        {
            settings.UseBackgroundEngine = wantBackground;
            if (wantBackground)
            {
                (Application.Current as Sentinel.App)?.StartBackgroundEngine();
            }
            else
            {
                App.Services.Daemon.Dispose();
            }
        }

        App.Services.Settings.Save();
    }

    private void Option_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_reloading) return;
        var settings = App.Services.Settings.Settings;
        settings.ParallelWorkers = ReadInt(ParallelWorkersBox.Text);
        settings.MaxFileSizeMb = ReadInt(MaxFileSizeBox.Text);
        settings.MaxScanSizeMb = ReadInt(MaxScanSizeBox.Text);
        settings.MaxScanTimeMs = ReadInt(MaxScanTimeBox.Text);
        App.Services.Settings.Save();
    }

    private static int ReadInt(string text) =>
        int.TryParse(text.Trim(), out int value) && value > 0 ? value : 0;

    private void OpenDataFolder_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Directory.CreateDirectory(AppPaths.Root);
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = AppPaths.Root,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Could not open folder", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void ClearHistory_Click(object sender, RoutedEventArgs e)
    {
        var confirm = MessageBox.Show("Delete the entire scan history?", "Clear history",
            MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (confirm != MessageBoxResult.Yes) return;
        App.Services.History.Clear();
        MessageBox.Show("Scan history cleared.", "Done", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private async void PurgeQuarantine_Click(object sender, RoutedEventArgs e)
    {
        var entries = App.Services.Quarantine.GetAll();
        if (entries.Count == 0)
        {
            MessageBox.Show("Quarantine is already empty.", "Nothing to delete", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var confirm = MessageBox.Show(
            $"Permanently delete all {entries.Count} quarantine item(s)?\n\n" +
            "Encrypted copies are overwritten before deletion. This cannot be undone.",
            "Confirm purge", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes) return;

        int done = 0;
        foreach (var entry in entries)
        {
            try
            {
                await App.Services.Quarantine.DeleteAsync(entry);
                done++;
            }
            catch
            {
                // Continue with the rest; failures are reported by the count.
            }
        }

        (Window.GetWindow(this) as MainWindow)?.DashboardView.RefreshQuarantineCount();
        MessageBox.Show($"{done} quarantine item(s) deleted.", "Purge complete", MessageBoxButton.OK, MessageBoxImage.Information);
    }
}
