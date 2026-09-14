using Haley.Internal;
using Haley.Models;
using System;
using System.IO;
using System.Text.Json;

namespace Haley.Utils
{
    public static partial class DeploymentUtils
    {
        public static DeploymentApplicationInfo ReadApplicationInfo(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("Application information path is required.", nameof(path));
            var resolved = Path.GetFullPath(path.Trim());
            var info = JsonSerializer.Deserialize<DeploymentApplicationInfo>(ReadBoundedText(resolved), DeploymentJson.CompactOptions)
                ?? throw new InvalidDataException("Application information is empty.");
            if (info.AdditionalFields != null && info.AdditionalFields.Count > 0)
                throw new InvalidDataException("Application information supports only product, version, features, and limits.");
            var normalized = NormalizeInput(new DeploymentRequestInput
            {
                Product = info.Product,
                ProductVersion = info.ProductVersion,
                Features = info.Features,
                Limits = info.Limits
            });
            return new DeploymentApplicationInfo
            {
                Product = normalized.Product,
                ProductVersion = normalized.ProductVersion,
                Features = NormalizeCatalog(normalized.Features),
                Limits = NormalizeLimits(normalized.Limits)
            };
        }
    }
}
