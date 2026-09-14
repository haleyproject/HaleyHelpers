using Haley.Internal;
using Haley.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

namespace Haley.Utils
{
    public static partial class DeploymentUtils
    {
        public static string PrepareGrant(DeploymentGrantInput input)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            var decoded = DecodeRequestEnvelope(input.RequestEnvelope);
            if (!decoded.IsValid || decoded.Request == null)
                throw new ArgumentException("The deployment request is invalid (" + (decoded.Error ?? "request.invalid") + ").", nameof(input));

            var request = decoded.Request;
            if (request.Version != SupportedVersion)
                throw new ArgumentException("The deployment request must be renewed before a grant can be issued.", nameof(input));
            var licenseId = NormalizeCode(input.LicenseId, nameof(input.LicenseId));
            var customer = NormalizeText(input.Customer, nameof(input.Customer), 200);
            if (!Enum.IsDefined(typeof(MachineLockMode), input.MachineLock))
                throw new ArgumentOutOfRangeException(nameof(input.MachineLock));
            if (input.ValidityDays < 1 || input.ValidityDays > 36525)
                throw new ArgumentOutOfRangeException(nameof(input.ValidityDays), "Validity must be between 1 and 36525 days.");
            if (input.GraceDays < 0 || input.GraceDays > 3650)
                throw new ArgumentOutOfRangeException(nameof(input.GraceDays), "Grace must be between 0 and 3650 days.");
            if (input.IssuedUtc == default)
                throw new ArgumentException("The issue time is required.", nameof(input.IssuedUtc));
            if (string.IsNullOrWhiteSpace(input.PrivateKey))
                throw new ArgumentException("The issuer private key is required.", nameof(input.PrivateKey));
            if (!EncryptionUtils.ASymmetric.Envelope.IsValidKeyName(input.Key))
                throw new ArgumentException("The issuer key name is invalid.", nameof(input.Key));

            var features = CopyFeatures(input.Features);
            var limits = CopyLimits(input.Limits);
            RequireExactCatalog(request.Features, features.Keys, "feature");
            ValidateSelectedMachineEvidence(request.MachineEvidence, input.MachineLock);

            var issued = input.IssuedUtc.ToUniversalTime();
            var expires = issued.AddDays(input.ValidityDays);
            var payload = new DeploymentGrantPayload
            {
                Version = SupportedVersion,
                LicenseId = licenseId,
                Product = request.Product,
                ProductVersion = request.ProductVersion,
                Customer = customer,
                Deployment = request.DeployId,
                DeployId = request.DeployId,
                RequestCreated = request.Created,
                DeployPrint = JsonSerializer.Deserialize<RequestEnvelope>(input.RequestEnvelope, DeploymentJson.CompactOptions)!.DeployPrint,
                MachineLock = input.MachineLock,
                MachineEvidence = request.MachineEvidence,
                Issued = issued,
                NotBefore = issued,
                Expires = expires,
                GraceDays = input.GraceDays,
                Features = features,
                Limits = limits
            };
            var json = JsonSerializer.Serialize(payload, DeploymentJson.CompactOptions);
            return EncryptionUtils.ASymmetric.Envelope.Prepare(json, input.PrivateKey, input.Key);
        }

        private static Dictionary<string, bool> CopyFeatures(IReadOnlyDictionary<string, bool>? values)
        {
            var result = new Dictionary<string, bool>(StringComparer.Ordinal);
            foreach (var item in values ?? new Dictionary<string, bool>())
            {
                result.Add(NormalizeCode(item.Key, "feature"), item.Value);
            }
            return result;
        }

        private static Dictionary<string, long> CopyLimits(IReadOnlyDictionary<string, long>? values)
        {
            var result = new Dictionary<string, long>(StringComparer.Ordinal);
            foreach (var item in values ?? new Dictionary<string, long>())
            {
                if (item.Value < 0) throw new ArgumentException("Limit values cannot be negative.", nameof(values));
                result.Add(NormalizeCode(item.Key, "limit"), item.Value);
            }
            return result;
        }

        private static void RequireExactCatalog(IEnumerable<string> available, IEnumerable<string> supplied, string kind)
        {
            var expected = available.OrderBy(item => item, StringComparer.Ordinal).ToArray();
            var actual = supplied.OrderBy(item => item, StringComparer.Ordinal).ToArray();
            if (!expected.SequenceEqual(actual, StringComparer.Ordinal))
                throw new ArgumentException("Issuer policy must explicitly contain exactly every advertised " + kind + ".");
        }

        private static void ValidateSelectedMachineEvidence(MachineEvidence evidence, MachineLockMode mode)
        {
            if (mode == MachineLockMode.Lite && evidence.Lite.Count < 1)
                throw new ArgumentException("The request does not contain Lite machine evidence.");
            if (mode == MachineLockMode.Strong && evidence.Strong.Count < 2)
                throw new ArgumentException("The request does not contain two Strong machine fingerprints.");
        }
    }
}
