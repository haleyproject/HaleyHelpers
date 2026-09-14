using Haley.Utils;

namespace Haley.Models
{
    public sealed class DeploymentOverrideInput
    {
        public string Request { get; set; } = string.Empty;
        public string PrivateKey { get; set; } = string.Empty;
        public string Key { get; set; } = RsaKeyNames.Default;
    }
}
