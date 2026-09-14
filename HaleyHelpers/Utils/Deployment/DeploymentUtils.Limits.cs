using Haley.Models;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;

namespace Haley.Utils
{
    public static partial class DeploymentUtils
    {
        internal static Dictionary<string, DeploymentLimitDefinition> NormalizeLimits(
            IReadOnlyDictionary<string, DeploymentLimitDefinition>? values)
        {
            var result = new Dictionary<string, DeploymentLimitDefinition>(StringComparer.Ordinal);
            foreach (var item in values ?? new Dictionary<string, DeploymentLimitDefinition>())
            {
                var code = NormalizeCode(item.Key, "limit code");
                if (item.Value == null) throw new ArgumentException("Limit definitions cannot be null.", nameof(values));
                result.Add(code, new DeploymentLimitDefinition
                {
                    DefaultValue = NormalizeLimitValue(item.Value.DefaultValue, code + " default"),
                    Description = NormalizeText(item.Value.Description, code + " description", 240)
                });
            }
            return result.OrderBy(item => item.Key, StringComparer.Ordinal)
                .ToDictionary(item => item.Key, item => item.Value, StringComparer.Ordinal);
        }

        internal static Dictionary<string, JsonElement> NormalizeLimitValues(
            IReadOnlyDictionary<string, JsonElement>? values)
        {
            var result = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
            foreach (var item in values ?? new Dictionary<string, JsonElement>())
            {
                var code = NormalizeCode(item.Key, "limit code");
                result.Add(code, NormalizeLimitValue(item.Value, code + " value"));
            }
            return result.OrderBy(item => item.Key, StringComparer.Ordinal)
                .ToDictionary(item => item.Key, item => item.Value, StringComparer.Ordinal);
        }

        internal static JsonElement NormalizeLimitValue(JsonElement value, string parameter)
        {
            switch (value.ValueKind)
            {
                case JsonValueKind.True:
                    return ClonePrimitive("true");
                case JsonValueKind.False:
                    return ClonePrimitive("false");
                case JsonValueKind.Number:
                    if (!value.TryGetInt64(out var number) || number < 0)
                        throw new ArgumentException("Numeric limit values must be non-negative whole numbers.", parameter);
                    return ClonePrimitive(number.ToString(CultureInfo.InvariantCulture));
                case JsonValueKind.String:
                    var text = NormalizeText(value.GetString() ?? string.Empty, parameter, 500);
                    return ClonePrimitive(JsonSerializer.Serialize(text));
                default:
                    throw new ArgumentException("Limit values must be a boolean, non-negative whole number, or string.", parameter);
            }
        }

        internal static bool LimitValueMatches(JsonElement expected, JsonElement actual)
            => string.Equals(CanonicalLimitValue(expected), CanonicalLimitValue(actual), StringComparison.Ordinal);

        internal static string CanonicalLimitValue(JsonElement value)
        {
            var normalized = NormalizeLimitValue(value, "limit value");
            return normalized.ValueKind switch
            {
                JsonValueKind.True => "boolean:true",
                JsonValueKind.False => "boolean:false",
                JsonValueKind.Number => "number:" + normalized.GetInt64().ToString(CultureInfo.InvariantCulture),
                JsonValueKind.String => "string:" + normalized.GetString(),
                _ => throw new ArgumentException("Unsupported limit value.", nameof(value))
            };
        }

        internal static string LimitType(JsonElement value)
        {
            return value.ValueKind switch
            {
                JsonValueKind.True or JsonValueKind.False => "boolean",
                JsonValueKind.Number => "number",
                JsonValueKind.String => "string",
                _ => "unsupported"
            };
        }

        internal static bool LimitCatalogMatches(
            IReadOnlyDictionary<string, DeploymentLimitDefinition> left,
            IReadOnlyDictionary<string, DeploymentLimitDefinition> right)
        {
            if (left.Count != right.Count) return false;
            foreach (var item in left)
            {
                if (!right.TryGetValue(item.Key, out var candidate)
                    || !LimitValueMatches(item.Value.DefaultValue, candidate.DefaultValue)
                    || !string.Equals(item.Value.Description, candidate.Description, StringComparison.Ordinal))
                {
                    return false;
                }
            }
            return true;
        }

        private static JsonElement ClonePrimitive(string json)
        {
            using (var document = JsonDocument.Parse(json))
            {
                return document.RootElement.Clone();
            }
        }
    }
}
