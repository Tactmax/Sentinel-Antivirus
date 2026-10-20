using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Sentinel.Models;

namespace Sentinel.Services;

public sealed class QuarantineException : Exception
{
    public QuarantineException(string message) : base(message) { }
    public QuarantineException(string message, Exception inner) : base(message, inner) { }
}

public sealed class QuarantineService
{
    private static readonly byte[] Magic = "SNQT1"u8.ToArray();
    private const int HeaderLength = 5 + 16; // magic + AES IV
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private byte[]? _key;

    public string QuarantineDirectory => AppPaths.QuarantineDir;

    private byte[] GetKey()
    {
        if (_key is not null) return _key;
        AppPaths.EnsureDirectories();
        if (File.Exists(AppPaths.QuarantineKeyFile))
        {
            try
            {
                byte[] wrapped = File.ReadAllBytes(AppPaths.QuarantineKeyFile);
                _key = ProtectedData.Unprotect(wrapped, null, DataProtectionScope.CurrentUser);
                return _key;
            }
            catch (Exception ex)
            {
                throw new QuarantineException(
                    "Sentinel cannot unlock the quarantine store. The key was protected for a different Windows user or machine, or the key file is damaged. " +
                    "Quarantined files cannot be restored or deleted securely until this is resolved.", ex);
            }
        }

        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] dpapi = ProtectedData.Protect(key, null, DataProtectionScope.CurrentUser);
        File.WriteAllBytes(AppPaths.QuarantineKeyFile, dpapi);
        _key = key;
        return _key;
    }

    public async Task<QuarantineEntry> QuarantineFileAsync(
        string sourcePath,
        string threat,
        string? expectedSha256,
        IProgress<string>? status = null,
        CancellationToken ct = default)
    {
        if (!File.Exists(sourcePath))
            throw new QuarantineException("The file no longer exists (it may have been removed by another program).");

        AppPaths.EnsureDirectories();
        byte[] key = GetKey();

        status?.Report("Verifying file integrity…");
        string sourceHash = await HashUtil.ComputeFileSha256Async(sourcePath, ct);
        if (!string.IsNullOrWhiteSpace(expectedSha256) &&
            !string.Equals(sourceHash, expectedSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new QuarantineException("The file changed after it was scanned. Run a new scan before quarantining it.");
        }

        string id = Guid.NewGuid().ToString("N");
        string payloadPath = Path.Combine(AppPaths.QuarantineDir, id + ".qtn");
        string tmpPath = payloadPath + ".tmp";
        string manifestPath = Path.Combine(AppPaths.QuarantineDir, id + ".json");
        long sizeBytes = new FileInfo(sourcePath).Length;

        var entry = new QuarantineEntry
        {
            Id = id,
            OriginalPath = sourcePath,
            FileName = Path.GetFileName(sourcePath),
            Threat = threat,
            Sha256 = sourceHash,
            SizeBytes = sizeBytes,
            QuarantinedAtUtc = DateTime.UtcNow,
            PayloadFile = Path.GetFileName(payloadPath),
            Encrypted = true,
            OriginalStillPresent = true
        };

        try
        {
            status?.Report("Encrypting into quarantine…");
            await using (var source = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read,
                             128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan))
            await using (var dest = new FileStream(tmpPath, FileMode.Create, FileAccess.Write, FileShare.None,
                             128 * 1024, FileOptions.Asynchronous))
            {
                byte[] iv = RandomNumberGenerator.GetBytes(16);
                await dest.WriteAsync(Magic, ct);
                await dest.WriteAsync(iv, ct);

                using var aes = Aes.Create();
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                using ICryptoTransform encryptor = aes.CreateEncryptor();
                await using (var crypto = new CryptoStream(dest, encryptor, CryptoStreamMode.Write, leaveOpen: true))
                {
                    await source.CopyToAsync(crypto, ct);
                    await crypto.FlushFinalBlockAsync(ct);
                }
            }

            status?.Report("Verifying quarantine copy…");
            string copyHash = await DecryptHashAsync(tmpPath, ct);
            if (!string.Equals(copyHash, sourceHash, StringComparison.OrdinalIgnoreCase))
            {
                File.Delete(tmpPath);
                throw new QuarantineException("The encrypted quarantine copy failed the integrity check. The original file was left untouched.");
            }

            await File.WriteAllTextAsync(manifestPath,
                JsonSerializer.Serialize(entry, JsonOptions), ct);
            File.Move(tmpPath, payloadPath, overwrite: true);
        }
        catch (OperationCanceledException)
        {
            TryDelete(tmpPath);
            TryDelete(payloadPath);
            throw;
        }
        catch (QuarantineException)
        {
            TryDelete(tmpPath);
            TryDelete(payloadPath);
            throw;
        }
        catch (Exception ex)
        {
            TryDelete(tmpPath);
            TryDelete(payloadPath);
            throw new QuarantineException($"Could not write the quarantine copy: {ex.Message}", ex);
        }

        status?.Report("Removing the original file…");
        try
        {
            File.Delete(sourcePath);
            entry.OriginalStillPresent = false;
            await SaveManifestAsync(entry, ct);
        }
        catch (Exception ex)
        {
            entry.OriginalStillPresent = true;
            await SaveManifestAsync(entry, ct);
            throw new QuarantineException(
                $"A verified, encrypted copy was placed in quarantine, but Windows could not delete the original file.\n\n" +
                $"Original: {sourcePath}\nReason: {ex.Message}", ex);
        }

        return entry;
    }

    public IReadOnlyList<QuarantineEntry> GetAll()
    {
        var entries = new List<QuarantineEntry>();
        if (Directory.Exists(AppPaths.QuarantineDir))
        {
            foreach (string manifest in Directory.EnumerateFiles(AppPaths.QuarantineDir, "*.json"))
            {
                QuarantineEntry? entry = TryReadManifest(manifest);
                if (entry is not null) entries.Add(entry);
            }
        }

        // Legacy prototype layout: %LOCALAPPDATA%\Sentinel\Manifests\*.json with plaintext payloads.
        if (Directory.Exists(AppPaths.LegacyManifestDir))
        {
            foreach (string manifest in Directory.EnumerateFiles(AppPaths.LegacyManifestDir, "*.json"))
            {
                QuarantineEntry? entry = TryReadLegacyManifest(manifest);
                if (entry is not null) entries.Add(entry);
            }
        }

        entries.Sort((a, b) => b.QuarantinedAtUtc.CompareTo(a.QuarantinedAtUtc));
        return entries;
    }

    public string GetPayloadPath(QuarantineEntry entry)
    {
        if (Path.IsPathRooted(entry.PayloadFile)) return entry.PayloadFile;
        return Path.Combine(AppPaths.QuarantineDir, entry.PayloadFile);
    }

    public async Task<bool> VerifyIntegrityAsync(QuarantineEntry entry, CancellationToken ct = default)
    {
        string payload = GetPayloadPath(entry);
        if (!File.Exists(payload)) return false;
        string hash = entry.Encrypted
            ? await DecryptHashAsync(payload, ct)
            : await HashUtil.ComputeFileSha256Async(payload, ct);
        return string.Equals(hash, entry.Sha256, StringComparison.OrdinalIgnoreCase);
    }

    public async Task RestoreAsync(
        QuarantineEntry entry,
        string targetPath,
        bool overwrite,
        IProgress<string>? status = null,
        CancellationToken ct = default)
    {
        string payload = GetPayloadPath(entry);
        if (!File.Exists(payload))
            throw new QuarantineException("The quarantine payload is missing. The item cannot be restored.");

        status?.Report("Verifying quarantine integrity…");
        string payloadHash = entry.Encrypted
            ? await DecryptHashAsync(payload, ct)
            : await HashUtil.ComputeFileSha256Async(payload, ct);
        if (!string.Equals(payloadHash, entry.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new QuarantineException("The quarantine copy does not match its recorded hash. Restore was cancelled to avoid writing a damaged or tampered file.");

        string? dir = Path.GetDirectoryName(targetPath);
        if (string.IsNullOrEmpty(dir))
            throw new QuarantineException("The restore location is not a valid directory.");
        if (!Directory.Exists(dir))
            Directory.CreateDirectory(dir);
        if (File.Exists(targetPath) && !overwrite)
            throw new QuarantineException("A file already exists at the restore location.");

        string tempPath = Path.Combine(dir, $".{Path.GetFileName(targetPath)}.sentinel-restore.tmp");
        try
        {
            status?.Report("Restoring file…");
            if (entry.Encrypted)
                await DecryptToFileAsync(payload, tempPath, ct);
            else
                File.Copy(payload, tempPath, overwrite: true);

            string restoredHash = await HashUtil.ComputeFileSha256Async(tempPath, ct);
            if (!string.Equals(restoredHash, entry.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new QuarantineException("The restored file failed its integrity check. The original location was not modified.");

            File.Move(tempPath, targetPath, overwrite: true);
        }
        finally
        {
            TryDelete(tempPath);
        }

        entry.RestoredAtUtc = DateTime.UtcNow;
        entry.RestorePath = targetPath;
        entry.OriginalStillPresent = false;
        await SaveManifestAsync(entry, ct);
    }

    public async Task DeleteAsync(QuarantineEntry entry, CancellationToken ct = default)
    {
        string payload = GetPayloadPath(entry);
        if (File.Exists(payload))
        {
            await OverwriteSecurelyAsync(payload, ct);
            TryDelete(payload);
        }

        string manifest = entry.Encrypted || !Path.IsPathRooted(entry.PayloadFile)
            ? Path.Combine(AppPaths.QuarantineDir, entry.Id + ".json")
            : Path.Combine(AppPaths.LegacyManifestDir, entry.Id + ".json");
        if (File.Exists(manifest)) TryDelete(manifest);

        if (Path.IsPathRooted(entry.PayloadFile))
        {
            string legacyPayload = entry.PayloadFile;
            if (File.Exists(legacyPayload)) await OverwriteSecurelyAsync(legacyPayload, ct);
        }
    }

    public async Task SaveManifestAsync(QuarantineEntry entry, CancellationToken ct = default)
    {
        AppPaths.EnsureDirectories();
        string manifestPath = Path.Combine(AppPaths.QuarantineDir, entry.Id + ".json");
        await File.WriteAllTextAsync(manifestPath, JsonSerializer.Serialize(entry, JsonOptions), ct);
    }

    private QuarantineEntry? TryReadManifest(string path)
    {
        try
        {
            var entry = JsonSerializer.Deserialize<QuarantineEntry>(File.ReadAllText(path), JsonOptions);
            if (entry is null || string.IsNullOrWhiteSpace(entry.Id)) return null;
            if (string.IsNullOrWhiteSpace(entry.PayloadFile))
                entry.PayloadFile = Path.ChangeExtension(path, ".qtn");
            return entry;
        }
        catch
        {
            return null;
        }
    }

    private sealed class LegacyManifest
    {
        public string Id { get; set; } = "";
        public string OriginalPath { get; set; } = "";
        public string QuarantinePath { get; set; } = "";
        public string Threat { get; set; } = "";
        public string Sha256 { get; set; } = "";
        public DateTime QuarantinedAtUtc { get; set; }
    }

    private QuarantineEntry? TryReadLegacyManifest(string path)
    {
        try
        {
            var legacy = JsonSerializer.Deserialize<LegacyManifest>(File.ReadAllText(path), JsonOptions);
            if (legacy is null || string.IsNullOrWhiteSpace(legacy.Id)) return null;
            if (!File.Exists(legacy.QuarantinePath)) return null;
            return new QuarantineEntry
            {
                Id = legacy.Id,
                OriginalPath = legacy.OriginalPath,
                FileName = Path.GetFileName(legacy.OriginalPath),
                Threat = legacy.Threat,
                Sha256 = legacy.Sha256,
                SizeBytes = new FileInfo(legacy.QuarantinePath).Length,
                QuarantinedAtUtc = legacy.QuarantinedAtUtc,
                PayloadFile = legacy.QuarantinePath,
                Encrypted = false,
                OriginalStillPresent = false,
                Notes = "Imported from an early prototype (plaintext payload)."
            };
        }
        catch
        {
            return null;
        }
    }

    private async Task<string> DecryptHashAsync(string payloadPath, CancellationToken ct)
    {
        await using var stream = new FileStream(payloadPath, FileMode.Open, FileAccess.Read, FileShare.Read,
            128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        return await DecryptHashAsync(stream, ct);
    }

    private async Task<string> DecryptHashAsync(Stream payloadStream, CancellationToken ct)
    {
        using ICryptoTransform decryptor = CreateDecryptor(payloadStream);
        await using var crypto = new CryptoStream(payloadStream, decryptor, CryptoStreamMode.Read, leaveOpen: true);
        try
        {
            return await HashUtil.ComputeStreamSha256Async(crypto, ct);
        }
        catch (CryptographicException ex)
        {
            throw new QuarantineException("The quarantine payload is corrupt or tampered with (decryption failed).", ex);
        }
    }

    private async Task DecryptToFileAsync(string payloadPath, string targetPath, CancellationToken ct)
    {
        await using var payload = new FileStream(payloadPath, FileMode.Open, FileAccess.Read, FileShare.Read,
            128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        using ICryptoTransform decryptor = CreateDecryptor(payload);
        await using var crypto = new CryptoStream(payload, decryptor, CryptoStreamMode.Read, leaveOpen: true);
        await using var target = new FileStream(targetPath, FileMode.Create, FileAccess.Write, FileShare.None,
            128 * 1024, FileOptions.Asynchronous);
        try
        {
            await crypto.CopyToAsync(target, ct);
        }
        catch (CryptographicException ex)
        {
            throw new QuarantineException("The quarantine payload is corrupt or tampered with (decryption failed).", ex);
        }
    }

    private ICryptoTransform CreateDecryptor(Stream payloadStream)
    {
        byte[] header = new byte[HeaderLength];
        ReadExact(payloadStream, header);
        for (int i = 0; i < Magic.Length; i++)
        {
            if (header[i] != Magic[i])
                throw new QuarantineException("The quarantine payload has an unknown format and cannot be restored.");
        }
        byte[] iv = header[Magic.Length..HeaderLength];
        using var aes = Aes.Create();
        aes.Key = GetKey();
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        return aes.CreateDecryptor();
    }

    private static void ReadExact(Stream stream, byte[] buffer)
    {
        int read = 0;
        while (read < buffer.Length)
        {
            int n = stream.Read(buffer, read, buffer.Length - read);
            if (n <= 0) throw new QuarantineException("The quarantine payload is truncated.");
            read += n;
        }
    }

    private static async Task OverwriteSecurelyAsync(string path, CancellationToken ct)
    {
        try
        {
            await using var fs = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None);
            long length = fs.Length;
            if (length == 0) return;
            byte[] block = RandomNumberGenerator.GetBytes(64 * 1024);
            fs.Position = 0;
            long remaining = length;
            while (remaining > 0)
            {
                int toWrite = (int)Math.Min(block.Length, remaining);
                await fs.WriteAsync(block.AsMemory(0, toWrite), ct);
                remaining -= toWrite;
            }
            await fs.FlushAsync(ct);
        }
        catch
        {
            // Best effort: fall through to a normal delete.
        }
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch { }
    }
}
