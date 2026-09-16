using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;

namespace Atlas.DotNetCandidate;

internal sealed record ProbeEvidence(
    string candidate,
    string host_runtime,
    string protocol,
    string protocol_version,
    bool session_nonce_echoed,
    string sidecar_sha256,
    long sidecar_size_bytes,
    string host_sha256,
    long host_size_bytes,
    double round_trip_ms,
    int stderr_bytes,
    JsonElement status_result);

internal static class CoreProbe
{
    private const int MaxResponse = 8 * 1024 * 1024;
    private static readonly string[] EnvAllowlist =
    [
        "PATH", "SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP",
        "USERPROFILE", "LOCALAPPDATA", "APPDATA"
    ];

    internal static async Task<ProbeEvidence> RunAsync()
    {
        var baseDir = AppContext.BaseDirectory;
        var core = Path.Combine(baseDir, "atlas-core.exe");
        var manifest = core + ".sha256";
        VerifySidecar(core, manifest);

        const string nonce = "phase561-dotnet-nonce";
        var requests = new object[]
        {
            new
            {
                id = "phase561-handshake",
                method = "core.handshake",
                @params = new
                {
                    protocol = "atlas-core",
                    version = "1.0.0",
                    client_name = "atlas-dotnet-candidate",
                    client_version = "0.1.0-dev",
                    session_nonce = nonce
                }
            },
            new { id = "phase561-status", method = "core.status", @params = new { } }
        };

        var startInfo = new ProcessStartInfo(core, "--serve-stdio")
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = baseDir
        };
        startInfo.Environment.Clear();
        foreach (var key in EnvAllowlist)
        {
            var value = Environment.GetEnvironmentVariable(key);
            if (!string.IsNullOrEmpty(value))
                startInfo.Environment[key] = value;
        }

        using var process = new Process { StartInfo = startInfo };
        if (!process.Start()) throw new InvalidOperationException("atlas-core failed to start");

        var stderrTask = process.StandardError.ReadToEndAsync();
        using var output = new MemoryStream();
        var stdoutTask = process.StandardOutput.BaseStream.CopyToAsync(output);

        foreach (var request in requests)
            await WriteFrameAsync(process.StandardInput.BaseStream, request);
        await process.StandardInput.BaseStream.FlushAsync();
        process.StandardInput.Close();

        var sw = Stopwatch.StartNew();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try
        {
            await process.WaitForExitAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException("atlas-core stdio probe timed out");
        }
        await stdoutTask;
        var stderr = await stderrTask;
        sw.Stop();

        if (process.ExitCode != 0)
            throw new InvalidOperationException($"atlas-core exited {process.ExitCode}: {stderr[..Math.Min(stderr.Length, 2000)]}");

        var responses = ParseFrames(output.ToArray());
        if (responses.Count != 2) throw new InvalidDataException($"expected 2 responses, got {responses.Count}");
        var handshake = responses.Single(x => x.RootElement.GetProperty("id").GetString() == "phase561-handshake");
        var status = responses.Single(x => x.RootElement.GetProperty("id").GetString() == "phase561-status");
        RequireOk(handshake.RootElement, "handshake");
        RequireOk(status.RootElement, "core.status");

        var result = handshake.RootElement.GetProperty("result");
        if (result.GetProperty("protocol").GetString() != "atlas-core") throw new InvalidDataException("protocol mismatch");
        if (result.GetProperty("version").GetString() != "1.0.0") throw new InvalidDataException("protocol version mismatch");
        if (result.GetProperty("session_nonce").GetString() != nonce) throw new InvalidDataException("session nonce mismatch");

        var coreInfo = new FileInfo(core);
        var host = Environment.ProcessPath ?? throw new InvalidOperationException("host executable path unavailable");
        var hostInfo = new FileInfo(host);
        return new ProbeEvidence(
            "dotnet-wpf",
            Environment.Version.ToString(),
            "atlas-core",
            "1.0.0",
            true,
            Sha256Hex(core),
            coreInfo.Length,
            Sha256Hex(host),
            hostInfo.Length,
            Math.Round(sw.Elapsed.TotalMilliseconds, 3),
            Encoding.UTF8.GetByteCount(stderr),
            status.RootElement.GetProperty("result").Clone());
    }

    private static void VerifySidecar(string core, string manifest)
    {
        if (!File.Exists(core)) throw new FileNotFoundException("atlas-core sidecar missing", core);
        if (!File.Exists(manifest)) throw new FileNotFoundException("atlas-core SHA-256 manifest missing", manifest);
        var expectedText = File.ReadAllText(manifest).Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)[0].ToLowerInvariant();
        if (expectedText.Length != 64) throw new InvalidDataException("invalid atlas-core SHA-256 manifest");
        var expected = Convert.FromHexString(expectedText);
        var actual = SHA256.HashData(File.ReadAllBytes(core));
        if (!CryptographicOperations.FixedTimeEquals(expected, actual)) throw new CryptographicException("atlas-core SHA-256 mismatch");
    }

    private static string Sha256Hex(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();

    private static async Task WriteFrameAsync(Stream stream, object payload)
    {
        var data = JsonSerializer.SerializeToUtf8Bytes(payload);
        var prefix = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(prefix, checked((uint)data.Length));
        await stream.WriteAsync(prefix);
        await stream.WriteAsync(data);
    }

    private static List<JsonDocument> ParseFrames(byte[] data)
    {
        var frames = new List<JsonDocument>();
        var offset = 0;
        while (offset < data.Length)
        {
            if (data.Length - offset < 4) throw new InvalidDataException("truncated response prefix");
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(offset, 4)));
            offset += 4;
            if (length <= 0 || length > MaxResponse) throw new InvalidDataException($"invalid frame length {length}");
            if (data.Length - offset < length) throw new InvalidDataException("truncated response payload");
            frames.Add(JsonDocument.Parse(data.AsMemory(offset, length)));
            offset += length;
        }
        return frames;
    }

    private static void RequireOk(JsonElement response, string operation)
    {
        if (!response.TryGetProperty("ok", out var ok) || ok.ValueKind != JsonValueKind.True)
            throw new InvalidDataException($"{operation} failed: {response}");
    }
}

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        try
        {
            if (args.Contains("--atlas-probe", StringComparer.Ordinal))
            {
                var output = ReadArg(args, "--probe-output") ?? throw new ArgumentException("--probe-output is required");
                var evidence = CoreProbe.RunAsync().GetAwaiter().GetResult();
                Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
                File.WriteAllText(output, JsonSerializer.Serialize(evidence, new JsonSerializerOptions { WriteIndented = true }) + Environment.NewLine);
                return 0;
            }

            var app = new Application();
            var text = new TextBox
            {
                IsReadOnly = true,
                TextWrapping = TextWrapping.Wrap,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Margin = new Thickness(20),
                FontFamily = new System.Windows.Media.FontFamily("Consolas"),
                FontSize = 14,
                Text = "Validating packaged atlas-core and requesting core.status..."
            };
            var window = new Window
            {
                Title = "Cyber-Sentinel ATLAS — .NET Candidate",
                Width = 900,
                Height = 620,
                Content = text
            };
            window.Loaded += async (_, _) =>
            {
                try
                {
                    var evidence = await CoreProbe.RunAsync();
                    text.Text = JsonSerializer.Serialize(evidence, new JsonSerializerOptions { WriteIndented = true });
                }
                catch (Exception ex)
                {
                    text.Text = "FAIL-CLOSED\n\n" + ex;
                }
            };
            app.Run(window);
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex);
            return 1;
        }
    }

    private static string? ReadArg(string[] args, string name)
    {
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] == name && i + 1 < args.Length) return args[i + 1];
            if (args[i].StartsWith(name + "=", StringComparison.Ordinal)) return args[i][(name.Length + 1)..];
        }
        return null;
    }
}
