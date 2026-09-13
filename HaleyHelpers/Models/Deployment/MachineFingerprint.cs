using System.Text.Json.Serialization;

namespace Haley.Models
{
    public sealed class MachineFingerprint
    {
        [JsonPropertyName("source")]
        public string Source { get; set; } = string.Empty;

        [JsonPropertyName("fingerprint")]
        public string Fingerprint { get; set; } = string.Empty;
    }
}
