using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Sentinel.Views;

namespace Sentinel;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        DashboardView.EngineStatusChanged += (_, _) => RefreshSidebarEngineText();
        ScanView.EngineStatusChanged += (_, _) => RefreshSidebarEngineText();
        QuarantineView.QuarantineChanged += (_, _) =>
        {
            DashboardView.RefreshQuarantineCount();
            ResultsView.Reload();
        };
        FitToWorkArea();
        RefreshSidebarEngineText();

        string? smokePage = Environment.GetEnvironmentVariable("SENTINEL_PAGE");
        if (!string.IsNullOrEmpty(smokePage))
        {
            Loaded += (_, _) => Navigate(smokePage);
        }

        string? shotPath = Environment.GetEnvironmentVariable("SENTINEL_SHOT");
        if (!string.IsNullOrEmpty(shotPath))
        {
            Loaded += async (_, _) => await CaptureAsync(shotPath);
        }
    }

    /// <summary>
    /// Renders the window straight to a PNG. Screen-grab tooling is unreliable
    /// (other windows steal focus, DPI virtualisation skews the output), so the
    /// app draws itself instead.
    /// </summary>
    private async Task CaptureAsync(string path)
    {
        try
        {
            int delay = 1500;
            if (int.TryParse(Environment.GetEnvironmentVariable("SENTINEL_SHOT_DELAY"), out int custom) && custom > 0)
                delay = custom;

            await Task.Delay(delay);
            UpdateLayout();
            await Task.Delay(200);

            double dpi = VisualTreeHelper.GetDpi(this).PixelsPerInchX;
            int width = Math.Max(1, (int)Math.Ceiling(ActualWidth * dpi / 96.0));
            int height = Math.Max(1, (int)Math.Ceiling(ActualHeight * dpi / 96.0));

            var target = new RenderTargetBitmap(width, height, dpi, dpi, PixelFormats.Pbgra32);
            target.Render(this);

            var encoder = new PngBitmapEncoder();
            encoder.Frames.Add(BitmapFrame.Create(target));
            using FileStream stream = File.Create(path);
            encoder.Save(stream);
        }
        catch (Exception ex)
        {
            try { File.WriteAllText(path + ".error.txt", ex.ToString()); } catch { }
        }
        finally
        {
            Application.Current.Shutdown();
        }
    }

    /// <summary>
    /// Keeps the window inside the usable desktop area. On a 150% display a fixed
    /// 1200x720 window would be 1800x1080 physical pixels - taller than the screen.
    /// </summary>
    private void FitToWorkArea()
    {
        Rect work = SystemParameters.WorkArea;
        if (work.Width <= 0 || work.Height <= 0) return;

        const double margin = 40;
        double width = Math.Min(1180, work.Width - margin);
        double height = Math.Min(780, work.Height - margin);
        if (width < 640) width = Math.Min(640, work.Width);
        if (height < 480) height = Math.Min(480, work.Height);

        Width = width;
        Height = height;
        MinWidth = Math.Min(880, work.Width);
        MinHeight = Math.Min(560, work.Height);
    }

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        ApplyDarkTitleBar();
    }

    /// <summary>Matches the Windows title bar to the dark application chrome.</summary>
    private void ApplyDarkTitleBar()
    {
        try
        {
            IntPtr hwnd = new WindowInteropHelper(this).Handle;
            int enabled = 1;
            // DWMWA_USE_IMMERSIVE_DARK_MODE (20, Windows 10 2004+),
            // with the older 19 attribute as a fallback.
            _ = DwmSetWindowAttribute(hwnd, 20, ref enabled, sizeof(int));
            _ = DwmSetWindowAttribute(hwnd, 19, ref enabled, sizeof(int));
        }
        catch
        {
            // Cosmetic only - never fail the app over a title bar colour.
        }
    }

    [DllImport("dwmapi.dll", SetLastError = true)]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    public void RefreshSidebarEngineText()
    {
        var engine = App.Services.Locator.Find(App.Services.Settings.Settings);
        if (engine is null)
        {
            SidebarEngineText.Text = "Not configured";
            SidebarStatusDot.Fill = FindResource("MutedBrush") as System.Windows.Media.Brush;
        }
        else
        {
            SidebarEngineText.Text = $"ClamAV {engine.EngineVersion ?? "?"} ready";
            SidebarStatusDot.Fill = FindResource("AccentBrush") as System.Windows.Media.Brush;
        }
        DashboardView.RefreshEngineState();
        ScanView.RefreshEngineState();
    }

    private void Nav_Click(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton { Tag: string tag }) Navigate(tag);
    }

    public void Navigate(string tag)
    {
        DashboardView.Visibility = tag == "dashboard" ? Visibility.Visible : Visibility.Collapsed;
        ScanView.Visibility = tag == "scan" ? Visibility.Visible : Visibility.Collapsed;
        ResultsView.Visibility = tag == "results" ? Visibility.Visible : Visibility.Collapsed;
        QuarantineView.Visibility = tag == "quarantine" ? Visibility.Visible : Visibility.Collapsed;
        HistoryView.Visibility = tag == "history" ? Visibility.Visible : Visibility.Collapsed;
        SettingsView.Visibility = tag == "settings" ? Visibility.Visible : Visibility.Collapsed;

        // Keep the sidebar highlight in step with the visible page.
        SetActiveNav(tag);

        if (tag == "dashboard")
        {
            DashboardView.RefreshEngineState();
            DashboardView.RefreshRecentActivity();
        }
        if (tag == "scan") ScanView.RefreshEngineState();
        if (tag == "results") ResultsView.Reload();
        if (tag == "quarantine") QuarantineView.Reload();
        if (tag == "history") HistoryView.Reload();
        if (tag == "settings") SettingsView.Reload();
    }

    private void SetActiveNav(string tag)
    {
        (string, RadioButton)[] items =
        [
            ("dashboard", NavDashboard),
            ("scan", NavScan),
            ("results", NavThreats),
            ("quarantine", NavQuarantine),
            ("history", NavHistory),
            ("settings", NavSettings)
        ];
        foreach ((string key, RadioButton button) in items)
            button.IsChecked = key == tag;
    }
}
