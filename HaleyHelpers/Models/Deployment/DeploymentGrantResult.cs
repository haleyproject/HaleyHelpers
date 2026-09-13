using System;
using System.Collections.Generic;

namespace Haley.Models
{
    public sealed class DeploymentGrantResult
    {
        public DeploymentGrantState State { get; internal set; }
        public string? Error { get; internal set; }
        public string? Message { get; internal set; }
        public string? Key { get; internal set; }
        public DeploymentGrantPayload? Payload { get; internal set; }
        public DeploymentRequest? Request { get; internal set; }
        public IReadOnlyDictionary<string, bool> Features { get; internal set; } = new Dictionary<string, bool>();
        public IReadOnlyDictionary<string, long> Limits { get; internal set; } = new Dictionary<string, long>();
        public IReadOnlyList<string> Warnings { get; internal set; } = Array.Empty<string>();
        public DateTimeOffset CheckedUtc { get; internal set; }
        public DateTimeOffset? GraceEndsUtc { get; internal set; }
        public DateTimeOffset? RecoveryEndsUtc { get; internal set; }
        public bool IsRecoveryActive { get; internal set; }
        public string? RequestPath { get; internal set; }
    }
}
