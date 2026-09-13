using System.Text.Json.Serialization;

namespace Haley.Models
{
    public sealed class RequestEnvelope
    {
        [JsonPropertyName("request")]
        public string Request { get; set; } = string.Empty;

        [JsonPropertyName("deploy_print")]
        public string DeployPrint { get; set; } = string.Empty;
    }
}
