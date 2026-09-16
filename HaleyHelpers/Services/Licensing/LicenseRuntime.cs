using Haley.Abstractions;
using Haley.Models;
using Haley.Utils;
using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Haley.Services
{
    /// <summary>
    /// Loads and holds one product's deployment license: reads <c>appinfo.json</c>, ensures the deployment request,
    /// evaluates the signed license and feature entitlement, and keeps the result as an in-memory
    /// <see cref="LicenseSnapshot"/>. Feature and limit checks never reread files. Replacing or reloading the license
    /// swaps the snapshot atomically, and a failed replacement leaves the active license untouched.
    /// </summary>
    public sealed class LicenseRuntime : IDisposable
    {
        public const string FeedbackSource = "Haley.Licensing";
        public const int MaxArtifactBytes = 256 * 1024;
        private const int ClientError = 400;
        private readonly SemaphoreSlim _gate = new SemaphoreSlim(1, 1);
        private readonly Func<DateTimeOffset> _clock;
        private readonly LicenseRuntimeOptions _options;
        private LicenseSnapshot _snapshot = null!;

        private LicenseRuntime(
            DeploymentApplicationInfo applicationInfo,
            string baseDirectory,
            string? deploymentInfoLocation,
            string licensePath,
            LicenseRuntimeOptions options,
            Func<DateTimeOffset> clock)
        {
            ApplicationInfo = applicationInfo;
            BaseDirectory = baseDirectory;
            DeploymentInfoLocation = deploymentInfoLocation;
            LicensePath = licensePath;
            _options = options;
            _clock = clock;
        }

        /// <summary>The validated product identity, version and catalogs from <c>appinfo.json</c>.</summary>
        public DeploymentApplicationInfo ApplicationInfo { get; }
        public string BaseDirectory { get; }
        public string? DeploymentInfoLocation { get; }
        public string LicensePath { get; }
        public DateTimeOffset Now => _clock().ToUniversalTime();

        /// <summary>The active snapshot. A grant that was not yet valid is evaluated again once its start time passes.</summary>
        public LicenseSnapshot Current => Snapshot(Now);

        /// <summary>
        /// Loads the license for a product. Fails when <c>appinfo.json</c> is unreadable or does not match the compiled
        /// catalogs, when the deployment request cannot be prepared, or when the grant is unusable.
        /// </summary>
        public static IFeedback<LicenseRuntime> Load(LicenseRuntimeOptions options)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));
            if (string.IsNullOrWhiteSpace(options.Product)) throw new ArgumentException("The product code is required.", nameof(options));
            if (options.TrialDays < 0 || options.TrialDays > 3650) throw new ArgumentOutOfRangeException(nameof(options), "Trial days must be between 0 and 3650.");
            if (options.ExpiringDays < 0 || options.ExpiringDays > 3650) throw new ArgumentOutOfRangeException(nameof(options), "Expiring days must be between 0 and 3650.");
            if (options.RecoveryDays < 0 || options.RecoveryDays > 365) throw new ArgumentOutOfRangeException(nameof(options), "Recovery days must be between 0 and 365.");

            var clock = options.Clock ?? (() => DateTimeOffset.UtcNow);
            var baseDirectory = Path.GetFullPath(string.IsNullOrWhiteSpace(options.BaseDirectory)
                ? AppContext.BaseDirectory
                : options.BaseDirectory!.Trim());
            var deploymentInfoLocation = string.IsNullOrWhiteSpace(options.DeploymentInfoLocation) ? null : options.DeploymentInfoLocation!.Trim();
            var applicationInfoPath = string.IsNullOrWhiteSpace(options.ApplicationInfoPath)
                ? Path.Combine(baseDirectory, "appinfo.json")
                : ResolvePath(options.ApplicationInfoPath!.Trim(), baseDirectory);

            DeploymentApplicationInfo applicationInfo;
            try
            {
                applicationInfo = DeploymentUtils.ReadApplicationInfo(applicationInfoPath);
            }
            catch (Exception exception) when (exception is IOException || exception is UnauthorizedAccessException
                || exception is InvalidDataException || exception is JsonException || exception is ArgumentException)
            {
                return Fail<LicenseRuntime>("license.appinfo_invalid",
                    "The application information file '" + applicationInfoPath + "' could not be read: " + exception.Message);
            }

            var mismatch = FindCatalogMismatch(applicationInfo, options);
            if (mismatch != null) return Fail<LicenseRuntime>("license.appinfo_mismatch", mismatch);

            var now = clock().ToUniversalTime();
            var request = DeploymentUtils.EnsureRequest(new DeploymentRequestInput
            {
                Product = applicationInfo.Product,
                ProductVersion = applicationInfo.ProductVersion,
                Features = applicationInfo.Features,
                Limits = applicationInfo.Limits,
                BaseDirectory = baseDirectory,
                DeploymentInfoLocation = deploymentInfoLocation,
                LicensePath = options.LicensePath,
                NowUtc = now
            });
            if (!request.IsValid || request.Request == null)
            {
                var detail = string.IsNullOrWhiteSpace(request.Message) ? string.Empty : ": " + request.Message;
                return Fail<LicenseRuntime>("license.request_unavailable",
                    "The deployment request could not be prepared (" + (request.Error ?? "request.invalid") + ")" + detail + ".");
            }

            var licensePath = DeploymentUtils.ResolveLicensePath(options.LicensePath, baseDirectory, deploymentInfoLocation);
            var runtime = new LicenseRuntime(applicationInfo, baseDirectory, deploymentInfoLocation, licensePath, options, clock);
            var snapshot = runtime.Evaluate(licensePath, now);
            if (!snapshot.IsUsable)
            {
                runtime.Dispose();
                return Fail<LicenseRuntime>("license.unusable", "The deployment grant is unusable (" + Reason(snapshot) + ").");
            }
            runtime._snapshot = snapshot;
            return Ok(runtime);
        }

        public LicenseStatus GetStatus()
        {
            var now = Now;
            return Snapshot(now).ToStatus(now);
        }

        public bool HasFeature(string feature)
        {
            var now = Now;
            return Snapshot(now).HasFeature(feature, now);
        }

        public bool TryGetLimit(string code, out long value)
        {
            var now = Now;
            return Snapshot(now).TryGetLimit(code, now, out value);
        }

        /// <summary>The signed deployment request envelope to send to the issuer.</summary>
        public IFeedback<string> GetRequest()
        {
            var request = DeploymentUtils.LoadRequest(new DeploymentRequestInput
            {
                Product = ApplicationInfo.Product,
                ProductVersion = ApplicationInfo.ProductVersion,
                Features = ApplicationInfo.Features,
                Limits = ApplicationInfo.Limits,
                BaseDirectory = BaseDirectory,
                DeploymentInfoLocation = DeploymentInfoLocation,
                NowUtc = Now
            });
            if (!request.IsValid || string.IsNullOrWhiteSpace(request.Envelope))
                return Fail<string>("license.request_unavailable",
                    "The deployment request is unavailable or invalid (" + (request.Error ?? "request.invalid") + "). Check the deployment files.");
            return Ok(request.Envelope!);
        }

        /// <summary>
        /// Verifies a replacement license before installing it. The previous file is kept beside it as
        /// <c>&lt;license&gt;.old-&lt;timestamp&gt;</c>, and the new snapshot is active without a restart.
        /// </summary>
        public async Task<IFeedback<LicenseStatus>> ReplaceAsync(Stream artifact, CancellationToken cancellationToken = default)
        {
            if (artifact == null) throw new ArgumentNullException(nameof(artifact));
            await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var read = await ReadBoundedAsync(artifact, cancellationToken).ConfigureAwait(false);
                if (!read.Status) return Fail<LicenseStatus>(read.Key, read.Message);

                var directory = Path.GetDirectoryName(LicensePath);
                if (string.IsNullOrWhiteSpace(directory))
                    return Fail<LicenseStatus>("license.path_invalid", "The license path has no containing directory.");
                var temporary = Path.Combine(directory, "." + Path.GetFileName(LicensePath) + "." + Guid.NewGuid().ToString("N") + ".tmp");
                try
                {
                    Directory.CreateDirectory(directory);
                    using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 16 * 1024, useAsync: true))
                    {
                        await stream.WriteAsync(read.Result, 0, read.Result.Length, cancellationToken).ConfigureAwait(false);
                    }

                    var now = Now;
                    var candidate = Evaluate(temporary, now);
                    if (!candidate.IsOperational)
                        return Fail<LicenseStatus>("license.replacement_invalid", "The replacement license is unusable (" + Reason(candidate) + ").");

                    if (File.Exists(LicensePath))
                        File.Replace(temporary, LicensePath, BuildBackupPath(now), ignoreMetadataErrors: true);
                    else
                        File.Move(temporary, LicensePath);

                    var active = Evaluate(LicensePath, now);
                    Interlocked.Exchange(ref _snapshot, active);
                    return Ok(active.ToStatus(now));
                }
                catch (Exception exception) when (exception is IOException || exception is UnauthorizedAccessException)
                {
                    return Fail<LicenseStatus>("license.replace_failed", "The license could not be installed: " + exception.Message);
                }
                finally
                {
                    TryDelete(temporary);
                }
            }
            finally
            {
                _gate.Release();
            }
        }

        /// <summary>Evaluates the installed files again. An unusable result is reported and the active snapshot is kept.</summary>
        public async Task<IFeedback<LicenseStatus>> ReloadAsync(CancellationToken cancellationToken = default)
        {
            await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var now = Now;
                var snapshot = Evaluate(LicensePath, now);
                if (!snapshot.IsUsable)
                    return Fail<LicenseStatus>("license.reload_invalid", "The configured license is unusable (" + Reason(snapshot) + ").");
                Interlocked.Exchange(ref _snapshot, snapshot);
                return Ok(snapshot.ToStatus(now));
            }
            finally
            {
                _gate.Release();
            }
        }

        public void Dispose() => _gate.Dispose();

        private LicenseSnapshot Snapshot(DateTimeOffset now)
        {
            var snapshot = Volatile.Read(ref _snapshot);
            if (snapshot.RefreshDueUtc is not { } due || now < due || !_gate.Wait(0)) return snapshot;
            try
            {
                snapshot = Volatile.Read(ref _snapshot);
                if (snapshot.RefreshDueUtc is { } stillDue && now >= stillDue)
                {
                    snapshot = Evaluate(LicensePath, now);
                    Interlocked.Exchange(ref _snapshot, snapshot);
                }
                return snapshot;
            }
            finally
            {
                _gate.Release();
            }
        }

        private LicenseSnapshot Evaluate(string licensePath, DateTimeOffset now)
        {
            var result = DeploymentUtils.EvaluateGrant(new DeploymentGrantOptions
            {
                LicensePath = licensePath,
                Product = ApplicationInfo.Product,
                ProductVersion = ApplicationInfo.ProductVersion,
                Features = ApplicationInfo.Features,
                Limits = ApplicationInfo.Limits,
                TrialLimits = ApplicationInfo.Limits.ToDictionary(item => item.Key, item => item.Value.DefaultValue, StringComparer.Ordinal),
                TrialDays = _options.TrialDays,
                ExpiringDays = _options.ExpiringDays,
                RecoveryDays = _options.RecoveryDays,
                PublicKeyPath = _options.PublicKeyPath,
                BaseDirectory = BaseDirectory,
                DeploymentInfoLocation = DeploymentInfoLocation,
                NowUtc = now
            });
            return new LicenseSnapshot(result, ApplicationInfo.Features, _options.ExpiringDays);
        }

        private static string? FindCatalogMismatch(DeploymentApplicationInfo info, LicenseRuntimeOptions options)
        {
            var product = options.Product.Trim().ToLowerInvariant();
            if (!string.Equals(info.Product, product, StringComparison.Ordinal))
                return "appinfo.json names product '" + info.Product + "' but the application is '" + product + "'.";
            if (options.Features != null && !Codes(options.Features).SequenceEqual(Codes(info.Features), StringComparer.Ordinal))
                return "appinfo.json features do not match the features compiled into " + product + ".";
            if (options.Limits != null && !Codes(options.Limits).SequenceEqual(Codes(info.Limits.Keys), StringComparer.Ordinal))
                return "appinfo.json limits do not match the limits compiled into " + product + ".";
            return null;
        }

        private static string[] Codes(System.Collections.Generic.IEnumerable<string> values)
            => values.Where(value => !string.IsNullOrWhiteSpace(value))
                .Select(value => value.Trim().ToLowerInvariant())
                .Distinct(StringComparer.Ordinal)
                .OrderBy(value => value, StringComparer.Ordinal)
                .ToArray();

        private static async Task<IFeedback<byte[]>> ReadBoundedAsync(Stream stream, CancellationToken cancellationToken)
        {
            using var buffer = new MemoryStream();
            var block = new byte[16 * 1024];
            while (true)
            {
                var read = await stream.ReadAsync(block, 0, block.Length, cancellationToken).ConfigureAwait(false);
                if (read == 0) break;
                if (buffer.Length + read > MaxArtifactBytes)
                    return Fail<byte[]>("license.artifact_too_large", "The license artifact exceeds 256 KB.");
                buffer.Write(block, 0, read);
            }
            return buffer.Length == 0
                ? Fail<byte[]>("license.artifact_empty", "The license artifact is empty.")
                : Ok(buffer.ToArray());
        }

        private string BuildBackupPath(DateTimeOffset now)
        {
            var stem = LicensePath + ".old-" + now.UtcDateTime.ToString("yyyyMMdd-HHmmssfff", System.Globalization.CultureInfo.InvariantCulture);
            var candidate = stem;
            for (var suffix = 1; File.Exists(candidate); suffix++) candidate = stem + "-" + suffix;
            return candidate;
        }

        private static void TryDelete(string path)
        {
            try
            {
                if (File.Exists(path)) File.Delete(path);
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        private static string ResolvePath(string path, string baseDirectory)
            => Path.GetFullPath(Path.IsPathRooted(path) ? path : Path.Combine(baseDirectory, path));

        private static string Reason(LicenseSnapshot snapshot) => snapshot.Grant.Error ?? snapshot.Grant.State.ToString();

        private static IFeedback<T> Ok<T>(T result)
            => new Feedback<T>(true).SetResult(result).SetSource(FeedbackSource);

        private static IFeedback<T> Fail<T>(string key, string message)
            => new Feedback<T>(false, message).SetKey(key).SetCode(ClientError).SetSource(FeedbackSource);
    }
}
