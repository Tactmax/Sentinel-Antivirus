// Mimics clamscan.exe output so the scanner integration can be tested without the real engine.
// Usage: Sentinel.StubEngine.exe <target> [<target> ...] [--recursive] [other ignored args]
// Behavior:
//  - prints "path: OK" per file, "path: Win.Test.EICAR FOUND" for files containing EICAR,
//    "path: Win.Test.SentinelStub FOUND" for files containing the Defender-safe test marker
//  - exit 0 if clean, 1 if detections, 2 if a target is missing
// The marker keeps the automated suite independent of Microsoft Defender's EICAR handling.

var targets = args.Where(a => !a.StartsWith("-", StringComparison.Ordinal)).ToArray();
if (targets.Length == 0 || targets.Any(t => !File.Exists(t) && !Directory.Exists(t)))
{
    Console.Error.WriteLine("ERROR: Can't stat() No such file or directory");
    return 2;
}

var files = new List<string>();
int directories = 0;
foreach (string target in targets)
{
    if (File.Exists(target))
    {
        files.Add(target);
    }
    else
    {
        directories++;
        foreach (string f in Directory.EnumerateFiles(target, "*", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true }))
            files.Add(f);
    }
}

const string eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
const string stubMarker = "SENTINEL-STUB-TEST-FILE";
int detections = 0;
foreach (string file in files)
{
    try
    {
        string text = File.ReadAllText(file);
        if (text.Contains(eicar, StringComparison.Ordinal))
        {
            Console.WriteLine($"{file}: Win.Test.EICAR FOUND");
            detections++;
            continue;
        }
        if (text.Contains(stubMarker, StringComparison.Ordinal))
        {
            Console.WriteLine($"{file}: Win.Test.SentinelStub FOUND");
            detections++;
            continue;
        }
    }
    catch
    {
        Console.WriteLine($"ERROR: Can't read {file}");
    }
    Console.WriteLine($"{file}: OK");
}

Console.WriteLine("----------- SCAN SUMMARY -----------");
Console.WriteLine("Known viruses: 8651234");
Console.WriteLine("Engine version: 9.99.1-stub");
Console.WriteLine($"Scanned directories: {directories}");
Console.WriteLine($"Scanned files: {files.Count}");
Console.WriteLine("Time: 0.050 sec");
return detections > 0 ? 1 : 0;
