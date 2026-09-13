using System;
using System.Collections.Generic;

namespace Haley.Models
{
    public sealed class MachineEvidenceResult
    {
        public MachineLockMode Mode { get; internal set; }
        public bool IsAvailable { get; internal set; }
        public IReadOnlyList<MachineFingerprint> Fingerprints { get; internal set; } = Array.Empty<MachineFingerprint>();
        public IReadOnlyList<string> MissingSources { get; internal set; } = Array.Empty<string>();
        public string? Error { get; internal set; }
    }
}
