using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using Sentinel.Models;

namespace Sentinel.Views;

public partial class HistoryView : UserControl
{
    public ObservableCollection<ScanSession> Sessions { get; } = new();

    public HistoryView()
    {
        InitializeComponent();
        SessionsGrid.ItemsSource = Sessions;
        Loaded += (_, _) => Reload();
    }

    public void Reload()
    {
        Sessions.Clear();
        foreach (ScanSession session in App.Services.History.Sessions) Sessions.Add(session);
        EmptyHint.Visibility = Sessions.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        if (Sessions.Count > 0 && SessionsGrid.SelectedIndex < 0)
            SessionsGrid.SelectedIndex = 0;
    }

    private void SessionsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (SessionsGrid.SelectedItem is not ScanSession session)
        {
            DetailTitle.Text = "Select a scan";
            DetailSubtitle.Text = "Pick a scan on the left to see what it found.";
            DetailGrid.ItemsSource = null;
            DetailGrid.Visibility = Visibility.Collapsed;
            DetailEmptyHint.Visibility = Visibility.Visible;
            DetailEmptyText.Text = "Nothing selected.";
            WarningsBox.Text = "";
            WarningsExpander.Visibility = Visibility.Collapsed;
            RescanButton.IsEnabled = false;
            return;
        }

        DetailTitle.Text = session.OutcomeLabel;
        DetailSubtitle.Text = $"{session.Target}\n{session.StartedLocal} · {session.ScannedFileCount:N0} files scanned · engine {session.EngineVersion}";

        DetailGrid.ItemsSource = session.Detections;
        bool hasDetections = session.Detections.Count > 0;
        DetailGrid.Visibility = hasDetections ? Visibility.Visible : Visibility.Collapsed;
        DetailEmptyHint.Visibility = hasDetections ? Visibility.Collapsed : Visibility.Visible;
        DetailEmptyText.Text = session.Outcome == "Cancelled"
            ? "This scan was cancelled before it finished."
            : "This scan found nothing.";

        WarningsBox.Text = session.Warnings.Count == 0 ? "No warnings." : string.Join(Environment.NewLine, session.Warnings);
        WarningsExpander.Visibility = session.Warnings.Count == 0 ? Visibility.Collapsed : Visibility.Visible;

        RescanButton.IsEnabled = true;
    }

    private void Rescan_Click(object sender, RoutedEventArgs e)
    {
        if (SessionsGrid.SelectedItem is not ScanSession session)
        {
            MessageBox.Show("Select a scan first.", "Nothing selected", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        string target = session.Target.Contains(';')
            ? session.Target.Split(';')[0].Trim()
            : session.Target;

        if (!File.Exists(target) && !Directory.Exists(target))
        {
            MessageBox.Show($"The original target no longer exists:\n{target}", "Cannot rescan",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var window = Window.GetWindow(this);
        if (window is MainWindow main)
        {
            main.Navigate("scan");
            _ = main.ScanView.SetTargetAndScan(target);
        }
    }

    private void Delete_Click(object sender, RoutedEventArgs e)
    {
        if (SessionsGrid.SelectedItem is not ScanSession session)
        {
            MessageBox.Show("Select a scan first.", "Nothing selected", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        App.Services.History.Delete(session.Id);
        Reload();
    }

    private void ClearAll_Click(object sender, RoutedEventArgs e)
    {
        var confirm = MessageBox.Show("Delete the entire scan history?", "Clear history",
            MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (confirm != MessageBoxResult.Yes) return;
        App.Services.History.Clear();
        Reload();
    }
}
