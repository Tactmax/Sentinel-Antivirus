using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using Sentinel.Models;

namespace Sentinel;

public sealed class KindToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => value switch
    {
        ScanItemKind.Detection => new SolidColorBrush(Color.FromRgb(0xFF, 0x5C, 0x7A)),
        ScanItemKind.Warning => new SolidColorBrush(Color.FromRgb(0xFF, 0xB4, 0x54)),
        _ => new SolidColorBrush(Color.FromRgb(0x42, 0xD3, 0x92))
    };

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

public sealed class InverseBoolConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is false;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is false;
}

/// <summary>Maps a scan outcome string to a status pill colour.</summary>
public sealed class OutcomeToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        string outcome = value?.ToString() ?? "";
        if (outcome.StartsWith("Detection", StringComparison.OrdinalIgnoreCase)) return new SolidColorBrush(Color.FromRgb(0xFF, 0x5C, 0x7A));
        if (outcome.StartsWith("Error", StringComparison.OrdinalIgnoreCase)) return new SolidColorBrush(Color.FromRgb(0xFF, 0x5C, 0x7A));
        if (outcome.StartsWith("Cancel", StringComparison.OrdinalIgnoreCase)) return new SolidColorBrush(Color.FromRgb(0x98, 0xA2, 0xAD));
        return new SolidColorBrush(Color.FromRgb(0x42, 0xD3, 0x92));
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>Maps a threat row's status to a text colour.</summary>
public sealed class ThreatStatusToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        string status = value?.ToString() ?? "";
        if (status.StartsWith("Quarantined", StringComparison.OrdinalIgnoreCase)) return new SolidColorBrush(Color.FromRgb(0x42, 0xD3, 0x92));
        if (status.StartsWith("Original missing", StringComparison.OrdinalIgnoreCase)) return new SolidColorBrush(Color.FromRgb(0x98, 0xA2, 0xAD));
        return new SolidColorBrush(Color.FromRgb(0xFF, 0xB4, 0x54));
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
