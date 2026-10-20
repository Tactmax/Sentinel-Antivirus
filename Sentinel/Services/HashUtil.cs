using System.IO;
using System.Security.Cryptography;

namespace Sentinel.Services;

public static class HashUtil
{
    public static async Task<string> ComputeFileSha256Async(string path, CancellationToken ct = default)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        byte[] hash = await SHA256.HashDataAsync(stream, ct);
        return Convert.ToHexString(hash);
    }

    public static async Task<string> ComputeStreamSha256Async(Stream stream, CancellationToken ct = default)
    {
        byte[] hash = await SHA256.HashDataAsync(stream, ct);
        return Convert.ToHexString(hash);
    }

    public static async Task<string> ComputeStreamSha256Async(Func<Stream> factory, CancellationToken ct = default)
    {
        using Stream stream = factory();
        return await ComputeStreamSha256Async(stream, ct);
    }
}
