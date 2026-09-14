using Haley.Models;
using Haley.Utils;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;

namespace Haley.Internal
{
    internal static class DeploymentRequestCanonicalizer
    {
        internal static string Create(DeploymentRequest request)
        {
            var builder = new StringBuilder();
            Append(builder, request.Version.ToString(CultureInfo.InvariantCulture));
            Append(builder, request.DeployId);
            Append(builder, request.Created.UtcDateTime.ToString("O", CultureInfo.InvariantCulture));

            if (request.Version > 1)
            {
                Append(builder, request.Product);
                Append(builder, request.ProductVersion);
                foreach (var feature in request.Features.OrderBy(item => item, StringComparer.Ordinal))
                {
                    Append(builder, feature);
                }
                if (request.Version >= 4)
                {
                    foreach (var limit in request.Limits.OrderBy(item => item.Key, StringComparer.Ordinal))
                    {
                        Append(builder, limit.Key);
                        Append(builder, DeploymentUtils.CanonicalLimitValue(limit.Value.DefaultValue));
                        Append(builder, limit.Value.Description);
                    }
                }
            }
            else
            {
                Append(builder, request.Deployment);
                Append(builder, request.Product);
                Append(builder, request.ProductVersion);
            }

            if (request.Version >= 3)
            {
                AppendProof(builder, "lite", request.MachineEvidence?.Lite);
                AppendProof(builder, "strong", request.MachineEvidence?.Strong);
            }
            else
            {
                foreach (var item in Enumerate(request.MachineEvidence))
                {
                    Append(builder, item.Source);
                    Append(builder, item.Fingerprint);
                }
            }

            return builder.ToString();
        }

        private static void AppendProof(StringBuilder builder, string mode, IEnumerable<MachineFingerprint>? values)
        {
            Append(builder, mode);
            foreach (var fingerprint in (values ?? Array.Empty<MachineFingerprint>())
                .Select(item => item.Fingerprint)
                .OrderBy(item => item, StringComparer.Ordinal))
            {
                Append(builder, fingerprint);
            }
        }

        private static IEnumerable<MachineFingerprint> Enumerate(MachineEvidence evidence)
        {
            return (evidence?.Lite ?? new List<MachineFingerprint>())
                .Concat(evidence?.Strong ?? new List<MachineFingerprint>())
                .OrderBy(item => item.Source, StringComparer.Ordinal)
                .ThenBy(item => item.Fingerprint, StringComparer.Ordinal);
        }

        private static void Append(StringBuilder builder, string value)
        {
            var safe = value ?? string.Empty;
            builder.Append(safe.Length.ToString(CultureInfo.InvariantCulture))
                .Append(':')
                .Append(safe)
                .Append('\n');
        }
    }
}
