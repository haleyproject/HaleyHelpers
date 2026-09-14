using System;
using System.Text.Json.Serialization;

namespace Haley.Models
{
    public sealed class DeploymentIdentity
    {
        [JsonPropertyName("version")]
        public int Version { get; set; }

        [JsonPropertyName("deployId")]
        public string DeployId { get; set; } = string.Empty;

        [JsonPropertyName("created")]
        public DateTimeOffset Created { get; set; }

        [JsonPropertyName("publicKeyHash")]
        public string PublicKeyHash { get; set; } = string.Empty;
    }
}
