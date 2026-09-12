using System.Text.Json.Serialization;

namespace Haley.Models
{
    public sealed class RsaEnvelope
    {
        [JsonPropertyName("payload")]
        public string Payload { get; set; } = string.Empty;

        [JsonPropertyName("signature")]
        public string Signature { get; set; } = string.Empty;

        [JsonPropertyName("key")]
        public string Key { get; set; } = string.Empty;
    }
}
