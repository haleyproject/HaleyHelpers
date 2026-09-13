using Haley.Enums;
using Haley.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Text;

namespace Haley.Utils
{
    public static partial class AssetUtils
    {
        private const string WindowsMachineGuidSource = "windows.machine-guid";
        private const string WindowsBoardSource = "windows.baseboard-serial";
        private const string WindowsProcessorSource = "windows.processor-id";
        private const string LinuxMachineIdSource = "linux.machine-id";
        private const string LinuxProductSource = "linux.dmi-product-uuid";
        private const string LinuxBoardSource = "linux.dmi-board-serial";

        public static MachineEvidenceResult GetMachineEvidence(MachineLockMode mode)
        {
            if (mode == MachineLockMode.None)
            {
                return new MachineEvidenceResult { Mode = mode, IsAvailable = true };
            }

            if (!Enum.IsDefined(typeof(MachineLockMode), mode))
            {
                return Unavailable(mode, "machine.mode_invalid", "machine-lock-mode");
            }

            try
            {
                return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                    ? GetWindowsEvidence(mode)
                    : RuntimeInformation.IsOSPlatform(OSPlatform.Linux)
                        ? GetLinuxEvidence(mode)
                        : Unavailable(mode, "machine.platform_unsupported", "supported-platform");
            }
            catch (Exception exception) when (exception is IOException
                || exception is UnauthorizedAccessException
                || exception is System.Management.ManagementException
                || exception is System.Security.SecurityException
                || exception is TargetInvocationException)
            {
                return Unavailable(mode, "machine.evidence_unavailable", "machine-evidence");
            }
        }

        internal static MachineFingerprint? GetMachineFingerprint(string source)
        {
            if (string.Equals(source, WindowsMachineGuidSource, StringComparison.Ordinal))
                return CreateFingerprint(source, ReadWindowsMachineGuid());
            if (string.Equals(source, WindowsBoardSource, StringComparison.Ordinal))
                return CreateFingerprint(source, ReadWindowsAsset(AssetIdentifier.MotherBoardID));
            if (string.Equals(source, WindowsProcessorSource, StringComparison.Ordinal))
                return CreateFingerprint(source, ReadWindowsAsset(AssetIdentifier.ProcessorID));
            if (string.Equals(source, LinuxMachineIdSource, StringComparison.Ordinal))
                return CreateFingerprint(source, ReadFirstFile("/etc/machine-id", "/var/lib/dbus/machine-id"));
            if (string.Equals(source, LinuxProductSource, StringComparison.Ordinal))
                return CreateFingerprint(source, ReadFirstFile("/sys/class/dmi/id/product_uuid"));
            if (string.Equals(source, LinuxBoardSource, StringComparison.Ordinal))
                return CreateFingerprint(source, ReadFirstFile("/sys/class/dmi/id/board_serial"));
            return null;
        }

        private static MachineEvidenceResult GetWindowsEvidence(MachineLockMode mode)
        {
            if (mode == MachineLockMode.Lite)
            {
                var value = ReadWindowsMachineGuid();
                return Build(mode, new[] { CreateFingerprint(WindowsMachineGuidSource, value) }, WindowsMachineGuidSource);
            }

            return Build(mode, new[]
            {
                CreateFingerprint(WindowsBoardSource, ReadWindowsAsset(AssetIdentifier.MotherBoardID)),
                CreateFingerprint(WindowsProcessorSource, ReadWindowsAsset(AssetIdentifier.ProcessorID))
            }, WindowsBoardSource, WindowsProcessorSource);
        }

        private static MachineEvidenceResult GetLinuxEvidence(MachineLockMode mode)
        {
            var machineId = ReadFirstFile("/etc/machine-id", "/var/lib/dbus/machine-id");
            if (mode == MachineLockMode.Lite)
            {
                return Build(mode, new[] { CreateFingerprint(LinuxMachineIdSource, machineId) }, LinuxMachineIdSource);
            }

            var candidates = new List<MachineFingerprint?>
            {
                CreateFingerprint(LinuxProductSource, ReadFirstFile("/sys/class/dmi/id/product_uuid")),
                CreateFingerprint(LinuxBoardSource, ReadFirstFile("/sys/class/dmi/id/board_serial"))
            };
            if (candidates.Where(item => item != null)
                .Cast<MachineFingerprint>()
                .Select(item => item.Fingerprint)
                .Distinct(StringComparer.Ordinal)
                .Count() < 2)
            {
                candidates.Add(CreateFingerprint(LinuxMachineIdSource, machineId));
            }

            var usable = candidates.Where(item => item != null)
                .Cast<MachineFingerprint>()
                .GroupBy(item => item.Fingerprint, StringComparer.Ordinal)
                .Select(group => group.First())
                .Take(2)
                .ToArray();
            if (usable.Length < 2)
            {
                return Unavailable(mode, "machine.strong_evidence_unavailable",
                    LinuxProductSource, LinuxBoardSource, LinuxMachineIdSource);
            }

            return new MachineEvidenceResult
            {
                Mode = mode,
                IsAvailable = true,
                Fingerprints = usable
            };
        }

        private static MachineEvidenceResult Build(
            MachineLockMode mode,
            IEnumerable<MachineFingerprint?> candidates,
            params string[] expectedSources)
        {
            var values = candidates.Where(item => item != null).Cast<MachineFingerprint>().ToArray();
            var required = mode == MachineLockMode.Strong ? 2 : 1;
            if (values.Length < required || values.Select(item => item.Fingerprint).Distinct(StringComparer.Ordinal).Count() < required)
            {
                return Unavailable(mode, mode == MachineLockMode.Strong
                    ? "machine.strong_evidence_unavailable"
                    : "machine.lite_evidence_unavailable", expectedSources);
            }

            return new MachineEvidenceResult
            {
                Mode = mode,
                IsAvailable = true,
                Fingerprints = values.Take(required).ToArray()
            };
        }

        private static MachineFingerprint? CreateFingerprint(string source, string? value)
        {
            var normalized = NormalizeMachineValue(value);
            if (normalized == null) return null;
            var protectedValue = "haley.machine.v1|" + source + "|" + normalized;
            return new MachineFingerprint
            {
                Source = source,
                Fingerprint = Convert.ToBase64String(HashUtils.ComputeHashBytes(protectedValue, HashMethod.Sha256)).SanitizeBase64()
            };
        }

        private static string? NormalizeMachineValue(string? value)
        {
            if (string.IsNullOrWhiteSpace(value)) return null;
            var normalized = value.Normalize(NormalizationForm.FormC).Trim().ToLowerInvariant();
            if (normalized.Length == 0 || normalized.Any(char.IsControl)) return null;

            var compact = new string(normalized.Where(character => !char.IsWhiteSpace(character) && character != '-').ToArray());
            if (compact.Length == 0 || compact.All(character => character == '0')) return null;
            var placeholders = new[]
            {
                "unknown", "none", "null", "default string", "to be filled by o.e.m.", "not specified", "system serial number"
            };
            return placeholders.Contains(normalized, StringComparer.Ordinal) ? null : compact;
        }

        private static string? ReadWindowsMachineGuid()
        {
            // Keep Haley.Helpers compatible with netstandard2.0 without forcing every
            // consumer to carry the Windows-only registry package. The registry assembly
            // is part of the Windows .NET runtime and is resolved only on Windows.
            var registryType = Type.GetType(
                "Microsoft.Win32.Registry, Microsoft.Win32.Registry",
                throwOnError: false);
            var localMachine = registryType?.GetField(
                "LocalMachine",
                BindingFlags.Public | BindingFlags.Static)?.GetValue(null);
            if (localMachine == null) return null;

            var openSubKey = localMachine.GetType().GetMethod(
                "OpenSubKey",
                new[] { typeof(string), typeof(bool) });
            var key = openSubKey?.Invoke(
                localMachine,
                new object[] { @"SOFTWARE\Microsoft\Cryptography", false }) as IDisposable;
            if (key == null) return null;

            using (key)
            {
                var getValue = key.GetType().GetMethod("GetValue", new[] { typeof(string) });
                return getValue?.Invoke(key, new object[] { "MachineGuid" })?.ToString();
            }
        }

        private static string? ReadWindowsAsset(AssetIdentifier identifier)
        {
            try { return GetId(identifier); }
            catch { return null; }
        }

        private static string? ReadFirstFile(params string[] paths)
        {
            foreach (var path in paths)
            {
                try
                {
                    if (!File.Exists(path)) continue;
                    var value = File.ReadAllText(path, Encoding.UTF8);
                    if (!string.IsNullOrWhiteSpace(value)) return value;
                }
                catch (Exception exception) when (exception is IOException || exception is UnauthorizedAccessException)
                {
                    continue;
                }
            }
            return null;
        }

        private static MachineEvidenceResult Unavailable(MachineLockMode mode, string error, params string[] missing)
        {
            return new MachineEvidenceResult
            {
                Mode = mode,
                IsAvailable = false,
                MissingSources = missing,
                Error = error
            };
        }
    }
}
