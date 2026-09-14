using System;
using System.Collections.Generic;

namespace Haley.Models
{
    public sealed class DeploymentRequestInput
    {
        public string Product { get; set; } = string.Empty;
        public string ProductVersion { get; set; } = string.Empty;
        public IReadOnlyCollection<string> Features { get; set; } = Array.Empty<string>();
        public string? BaseDirectory { get; set; }
        public DateTimeOffset? NowUtc { get; set; }
    }
}
