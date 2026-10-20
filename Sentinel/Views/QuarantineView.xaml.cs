using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using Sentinel.Models;
using Sentinel.Services;

namespace Sentinel.Views;

public partial class QuarantineView : UserControl
{
    public ObservableCollection<QuarantineEntry> Entries { get; } = new();
    public event EventHandler? QuarantineChanged;

    public QuarantineView()
    {
        InitializeComponent();
        EntriesGrid.ItemsSource = Entries;
        Loaded += (_, _) => Reload();
    }

    public void Reload()
    {
        Entries.Clear();
        try
        {
            foreach (QuarantineEntry entry in App.Services.Quarantine.GetAll()) Entries.Add(entry);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"The quarantine list could not be loaded:\n\n{ex.Message}", "Quarantine",
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        EmptyHint.Visibility = Entries.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        EntriesGrid.Visibility = Entries.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
        QuarantineChanged?.Invoke(this, EventArgs.Empty);
    }

    private QuarantineEntry? Selected => EntriesGrid.SelectedItem as QuarantineEntry;

    private void Refresh_Click(object sender, RoutedEventArgs e) => Reload();

    private void OpenFolder_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Directory.CreateDirectory(AppPaths.QuarantineDir);
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = AppPaths.QuarantineDir,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Could not open folder", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private async void Verify_Click(object sender, RoutedEventArgs e)
    {
        var targets = EntriesGrid.SelectedItems.OfType<QuarantineEntry>().ToList();
        if (targets.Count == 0)
        {
            MessageBox.Show("Select one or more quarantine entries to verify.", "Nothing selected",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        int ok = 0;
        var bad = new List<string>();
        foreach (QuarantineEntry entry in targets)
        {
            try
            {
                bool valid = await App.Services.Quarantine.VerifyIntegrityAsync(entry);
                if (valid) ok++;
                else bad.Add($"{entry.FileName}: hash mismatch or missing payload");
            }
            catch (Exception ex)
            {
                bad.Add($"{entry.FileName}: {ex.Message}");
            }
        }

        string message = $"{ok} of {targets.Count} item(s) passed the integrity check.";
        if (bad.Count > 0) message += "\n\n" + string.Join("\n", bad);
        MessageBox.Show(message, "Integrity check", MessageBoxButton.OK,
            bad.Count == 0 ? MessageBoxImage.Information : MessageBoxImage.Warning);
    }

    private async void Restore_Click(object sender, RoutedEventArgs e)
    {
        if (EntriesGrid.SelectedItem is not QuarantineEntry entry)
        {
            MessageBox.Show("Select a quarantine entry to restore.", "Nothing selected",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var warning = MessageBox.Show(
            $"Restore this file?\n\nThreat: {entry.Threat}\nOriginal location: {entry.OriginalPath}\n\n" +
            "Only restore a file if you are confident it is a false positive or you know exactly what it is. " +
            "Restored files are written unencrypted and may be executed.",
            "Confirm restore", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (warning != MessageBoxResult.Yes) return;

        string targetPath = entry.OriginalPath;
        bool overwrite = false;

        if (File.Exists(targetPath))
        {
            var options = MessageBox.Show(
                $"A file already exists at:\n{targetPath}\n\n" +
                "Yes = overwrite it (the existing file is replaced)\n" +
                "No = save the restored copy next to it with a new name\nCancel = abort the restore",
                "Target exists", MessageBoxButton.YesNoCancel, MessageBoxImage.Question);
            if (options == MessageBoxResult.Cancel) return;
            if (options == MessageBoxResult.Yes)
            {
                overwrite = true;
            }
            else
            {
                targetPath = MakeAlternatePath(targetPath);
            }
        }
        else
        {
            string? dir = Path.GetDirectoryName(targetPath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                var create = MessageBox.Show(
                    $"The original folder no longer exists:\n{dir}\n\nCreate it and restore the file there?",
                    "Folder missing", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (create != MessageBoxResult.Yes)
                {
                    var save = new SaveFileDialog
                    {
                        Title = "Choose where to restore the file",
                        FileName = Path.GetFileName(targetPath),
                        OverwritePrompt = true
                    };
                    if (save.ShowDialog() != true) return;
                    targetPath = save.FileName;
                }
            }
        }

        try
        {
            var progress = new Progress<string>(status => { /* restore is quick; dialog would be noisy */ });
            await App.Services.Quarantine.RestoreAsync(entry, targetPath, overwrite, progress, CancellationToken.None);

            var followUp = MessageBox.Show(
                $"Restored to:\n{targetPath}\n\nThe file passed its SHA-256 integrity check.\n\n" +
                "Remove the item from quarantine as well?\nYes = delete the encrypted quarantine copy\nNo = keep it listed here",
                "Restore complete", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (followUp == MessageBoxResult.Yes)
            {
                await App.Services.Quarantine.DeleteAsync(entry);
                MessageBox.Show("The quarantine copy was deleted.", "Removed", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            Reload();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Restore failed:\n\n{ex.Message}", "Restore error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private static string MakeAlternatePath(string path)
    {
        string dir = Path.GetDirectoryName(path) ?? ".";
        string name = Path.GetFileNameWithoutExtension(path);
        string ext = Path.GetExtension(path);
        for (int i = 1; ; i++)
        {
            string candidate = Path.Combine(dir, $"{name} (restored {i}){ext}");
            if (!File.Exists(candidate)) return candidate;
        }
    }

    private async void Delete_Click(object sender, RoutedEventArgs e)
    {
        var targets = EntriesGrid.SelectedItems.OfType<QuarantineEntry>().ToList();
        if (targets.Count == 0)
        {
            MessageBox.Show("Select one or more quarantine entries to delete.", "Nothing selected",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var confirm = MessageBox.Show(
            $"Permanently delete {targets.Count} quarantine item(s)?\n\n" +
            "The encrypted copies are overwritten before deletion. This cannot be undone, and the files cannot be restored afterwards.",
            "Confirm permanent deletion", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes) return;

        int done = 0;
        var errors = new List<string>();
        foreach (QuarantineEntry entry in targets)
        {
            try
            {
                await App.Services.Quarantine.DeleteAsync(entry);
                done++;
            }
            catch (Exception ex)
            {
                errors.Add($"{entry.FileName}: {ex.Message}");
            }
        }

        if (errors.Count > 0)
        {
            MessageBox.Show($"{done} deleted, {errors.Count} failed:\n\n" + string.Join("\n", errors),
                "Delete finished with problems", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        Reload();
    }
}
