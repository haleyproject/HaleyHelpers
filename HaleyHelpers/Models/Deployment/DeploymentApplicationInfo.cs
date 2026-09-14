using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Haley.Models
{
    public sealed class DeploymentApplicationInfo
    {
        [JsonPropertyName("product")]
        public string Product { get; set; } = string.Empty;

        [JsonPropertyName("version")]
        public string ProductVersion { get; set; } = string.Empty;

        [JsonPropertyName("features")]
        public List<string> Features { get; set; } = new List<string>();

        [JsonPropertyName("limits")]
        public Dictionary<string, DeploymentLimitDefinition> Limits { get; set; } = new Dictionary<string, DeploymentLimitDefinition>();

        [JsonExtensionData]
        public Dictionary<string, JsonElement>? AdditionalFields { get; set; }
    }
}
