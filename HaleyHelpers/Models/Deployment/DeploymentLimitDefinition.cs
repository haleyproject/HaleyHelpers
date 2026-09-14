using System.Text.Json;
using System.Text.Json.Serialization;

namespace Haley.Models
{
    public sealed class DeploymentLimitDefinition
    {
        [JsonPropertyName("default")]
        public JsonElement DefaultValue { get; set; }

        [JsonPropertyName("description")]
        public string Description { get; set; } = string.Empty;
    }
}
