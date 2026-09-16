using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using System.Text.Json;

namespace Haley.Models
{
    public sealed class DeploymentGrantPayload
    {
        [JsonPropertyName("version")]
        public int Version { get; set; }

        [JsonPropertyName("licenseId")]
        public string LicenseId { get; set; } = string.Empty;

        [JsonPropertyName("product")]
        public string Product { get; set; } = string.Empty;

        [JsonPropertyName("productVersion")]
        public string ProductVersion { get; set; } = string.Empty;

        [JsonPropertyName("customer")]
        public string Customer { get; set; } = string.Empty;

        [JsonPropertyName("deployment")]
        public string Deployment { get; set; } = string.Empty;

        [JsonPropertyName("deployId")]
        public string DeployId { get; set; } = string.Empty;

        [JsonPropertyName("requestCreated")]
        public DateTimeOffset RequestCreated { get; set; }

        [JsonPropertyName("deployPrint")]
        public string DeployPrint { get; set; } = string.Empty;

        [JsonPropertyName("binding")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Binding { get; set; }

        [JsonPropertyName("machineLock")]
        public MachineLockMode MachineLock { get; set; }

        [JsonPropertyName("proof")]
        public MachineEvidence MachineEvidence { get; set; } = new MachineEvidence();

        [JsonPropertyName("machineEvidence")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public MachineEvidence? LegacyMachineEvidence
        {
            get => null;
            set
            {
                if (value != null) MachineEvidence = value;
            }
        }

        [JsonPropertyName("issued")]
        public DateTimeOffset Issued { get; set; }

        [JsonPropertyName("notBefore")]
        public DateTimeOffset NotBefore { get; set; }

        [JsonPropertyName("expires")]
        public DateTimeOffset Expires { get; set; }

        [JsonPropertyName("graceDays")]
        public int GraceDays { get; set; }

        [JsonPropertyName("features")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public Dictionary<string, bool>? Features { get; set; }

        [JsonPropertyName("limits")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public Dictionary<string, JsonElement>? Limits { get; set; }

        [JsonPropertyName("limitCatalog")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public Dictionary<string, DeploymentLimitDefinition>? LimitCatalog { get; set; }
    }
}
