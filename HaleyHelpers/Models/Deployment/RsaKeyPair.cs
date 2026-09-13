namespace Haley.Models
{
    public sealed class RsaKeyPair
    {
        public string PrivateKey { get; internal set; } = string.Empty;
        public string PublicKey { get; internal set; } = string.Empty;
    }
}
