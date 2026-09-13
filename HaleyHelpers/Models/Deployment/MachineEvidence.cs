using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Haley.Models
{
    public sealed class MachineEvidence
    {
        [JsonPropertyName("lite")]
        public List<MachineFingerprint> Lite { get; set; } = new List<MachineFingerprint>();

        [JsonPropertyName("strong")]
        public List<MachineFingerprint> Strong { get; set; } = new List<MachineFingerprint>();
    }
}
