using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;

string outPath = args.Length > 0 ? args[0] : @"..\..\..\..\Sentinel\Resources\sentinel.ico";
outPath = Path.GetFullPath(outPath);
Directory.CreateDirectory(Path.GetDirectoryName(outPath)!);

byte[] RenderFrame(int size)
{
    var dv = new DrawingVisual();
    using (DrawingContext dc = dv.RenderOpen())
    {
        double s = size / 256.0;
        dc.PushTransform(new ScaleTransform(s, s));

        var gradient = new LinearGradientBrush(Color.FromRgb(0x42, 0xD3, 0x92), Color.FromRgb(0x14, 0x8C, 0x64), new Point(0, 0), new Point(1, 1));

        var group = new GeometryGroup { FillRule = FillRule.Nonzero };
        group.Children.Add(new RectangleGeometry(new Rect(28, 24, 200, 120), 8, 8));
        var tri = new PathGeometry();
        var fig = new PathFigure { StartPoint = new Point(28, 132), IsClosed = true };
        fig.Segments.Add(new LineSegment(new Point(128, 236), isStroked: true));
        fig.Segments.Add(new LineSegment(new Point(228, 132), isStroked: true));
        tri.Figures.Add(fig);
        group.Children.Add(tri);

        dc.DrawGeometry(gradient, new Pen(Brushes.White, 10) { LineJoin = PenLineJoin.Round }, group);

        var check = new PathGeometry();
        var cf = new PathFigure { StartPoint = new Point(70, 120) };
        cf.Segments.Add(new LineSegment(new Point(112, 160), true));
        cf.Segments.Add(new LineSegment(new Point(188, 78), true));
        check.Figures.Add(cf);
        dc.DrawGeometry(null, new Pen(Brushes.White, 22)
        {
            StartLineCap = PenLineCap.Round,
            EndLineCap = PenLineCap.Round,
            LineJoin = PenLineJoin.Round
        }, check);
    }

    var rtb = new RenderTargetBitmap(size, size, 96, 96, PixelFormats.Pbgra32);
    rtb.Render(dv);
    var enc = new PngBitmapEncoder();
    enc.Frames.Add(BitmapFrame.Create(rtb));
    using var ms = new MemoryStream();
    enc.Save(ms);
    return ms.ToArray();
}

int[] sizes = [16, 24, 32, 48, 64, 128, 256];
byte[][] frames = sizes.Select(RenderFrame).ToArray();

using var fs = new FileStream(outPath, FileMode.Create, FileAccess.Write);
using var bw = new BinaryWriter(fs);
bw.Write((ushort)0);
bw.Write((ushort)1);
bw.Write((ushort)sizes.Length);
int offset = 6 + 16 * sizes.Length;
for (int i = 0; i < sizes.Length; i++)
{
    bw.Write((byte)(sizes[i] >= 256 ? 0 : sizes[i]));
    bw.Write((byte)(sizes[i] >= 256 ? 0 : sizes[i]));
    bw.Write((byte)0);
    bw.Write((byte)0);
    bw.Write((ushort)1);
    bw.Write((ushort)32);
    bw.Write(frames[i].Length);
    bw.Write(offset);
    offset += frames[i].Length;
}
foreach (byte[] f in frames) bw.Write(f);
bw.Flush();
Console.WriteLine($"Icon written: {new FileInfo(outPath).Length} bytes -> {outPath}");
