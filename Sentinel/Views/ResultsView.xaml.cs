using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using Sentinel.Models;
using Sentinel.Services;

namespace Sentinel.Views;

public sealed class ThreatRow : INotifyPropertyChanged
{
    private string _status = "";

    public string Threat { get; set; } = "";
    public string Path { get; set; } = "";
    public string Sha256 { get; set; } = "";
    public string Sha256Short => Sha256.Length > 12 ? Sha256[..12] + "…" : Sha256;
    public string DetectedLocal { get; set; } = "";
    public string SessionId { get; set; } = "";

    public string Status
    {
        get => _status;
        set { _status = value; Raise(); }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void Raise([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

/// <summary>
/// Aggregates every detection Sentinel has recorded, so a user can review old and
/// new findings in one place instead of digging through individual scan history.
/// </summary>
public partial class ResultsView : UserControl
{
    private readonly ObservableCollection<ThreatRow> _all = new();

    public ObservableCollection<ThreatRow> Threats { get; } = new();

    public ResultsView()
    {
        InitializeComponent();
        ThreatsGrid.ItemsSource = Threats;
        Loaded += (_, _) => Reload();
    }

    public void Reload()
    {
        _all.Clear();
        HashSet<string> quarantinedPaths = BuildQuarantinedPathSet();

        foreach (ScanSession session in App.Services.History.Sessions)
        {
            foreach (ScanResultItem item in session.Detections)
            {
                bool quarantined = quarantinedPaths.Contains(item.Path);
                _all.Add(new ThreatRow
                {
                    Threat = item.Threat,
                    Path = item.Path,
                    Sha256 = item.Sha256,
                    DetectedLocal = session.StartedLocal,
                    SessionId = session.Id,
                    Status = quarantined
                        ? "Quarantined"
                        : File.Exists(item.Path) ? "Original present" : "Original missing"
                });
            }
        }

        ApplyFilter();
        RefreshSummary();
    }

    private HashSet<string> BuildQuarantinedPathSet()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (QuarantineEntry entry in App.Services.Quarantine.GetAll())
                set.Add(entry.OriginalPath);
        }
        catch
        {
            // Quarantine may be locked by another user; treat as unknown.
        }
        return set;
    }

    private void ApplyFilter()
    {
        string filter = SearchBox.Text.Trim();
        Threats.Clear();
        foreach (ThreatRow row in _all)
        {
            if (filter.Length == 0 ||
                row.Threat.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                row.Path.Contains(filter, StringComparison.OrdinalIgnoreCase))
            {
                Threats.Add(row);
            }
        }
        EmptyHint.Visibility = Threats.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        ThreatsGrid.Visibility = Threats.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
    }

    private void RefreshSummary()
    {
        int total = _all.Count;
        SummaryText.Visibility = total == 0 ? Visibility.Collapsed : Visibility.Visible;
        if (total == 0)
        {
            SummaryText.Text = "";
            return;
        }
        int quarantined = _all.Count(r => r.Status.StartsWith("Quarantined", StringComparison.OrdinalIgnoreCase));
        int missing = _all.Count(r => r.Status.StartsWith("Original missing", StringComparison.OrdinalIgnoreCase));
        SummaryText.Text = $"{total} detection(s) across your scan history · {quarantined} quarantined · {missing} original file no longer present.";
    }

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e) => ApplyFilter();

    private void Refresh_Click(object sender, RoutedEventArgs e) => Reload();

    private void ThreatsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e) => UpdateQuarantineButton();

    private void UpdateQuarantineButton() =>
        QuarantineButton.IsEnabled = ThreatsGrid.SelectedItem is ThreatRow { Status: "Original present" };

    private void ThreatsGrid_DoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        OpenSelected();
    }

    private void OpenLocation_Click(object sender, RoutedEventArgs e) => OpenSelected();

    private void OpenSelected()
    {
        if (ThreatsGrid.SelectedItem is not ThreatRow row) return;
        if (File.Exists(row.Path)) ProcessStartUtil.OpenInExplorer(row.Path);
        else if (Directory.Exists(row.Path)) ProcessStartUtil.OpenFolder(row.Path);
        else MessageBox.Show("That path no longer exists.", "Not found", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private async void Quarantine_Click(object sender, RoutedEventArgs e)
    {
        var rows = ThreatsGrid.SelectedItems.OfType<ThreatRow>()
            .Where(r => r.Status == "Original present").ToList();
        if (rows.Count == 0)
        {
            MessageBox.Show("Select a detection whose original file is still present.", "Nothing to quarantine",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var confirm = MessageBox.Show(
            rows.Count == 1
                ? $"Quarantine this file?\n\n{rows[0].Path}\n\nIt will be encrypted, verified, and removed from its current location."
                : $"Quarantine {rows.Count} detected files?\n\nEach will be encrypted, verified, and removed from its current location.",
            "Confirm quarantine", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes) return;

        int ok = 0;
        var failures = new List<string>();
        foreach (ThreatRow row in rows)
        {
            try
            {
                string hash = row.Sha256;
                if (string.IsNullOrEmpty(hash)) hash = await HashUtil.ComputeFileSha256Async(row.Path);
                await App.Services.Quarantine.QuarantineFileAsync(row.Path, row.Threat, hash);
                row.Sha256 = hash;
                row.Status = "Quarantined";
                ok++;
            }
            catch (Exception ex)
            {
                failures.Add($"{row.Path}\n  {ex.Message}");
            }
        }

        RefreshSummary();
        UpdateQuarantineButton();
        (Window.GetWindow(this) as MainWindow)?.DashboardView.RefreshQuarantineCount();

        if (failures.Count > 0)
        {
            MessageBox.Show(
                $"{ok} file(s) quarantined. Some items need attention:\n\n" + string.Join("\n\n", failures.Take(5)),
                "Quarantine finished with problems", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        else
        {
            MessageBox.Show($"{ok} file(s) moved to encrypted quarantine.", "Quarantine complete",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }
}
