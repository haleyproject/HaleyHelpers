namespace Haley.Models
{
    public sealed class RsaVerificationResult
    {
        public bool IsValid { get; internal set; }
        public string? Key { get; internal set; }
        public string? Payload { get; internal set; }
        public string? Error { get; internal set; }

        internal static RsaVerificationResult Valid(string key, string payload)
        {
            return new RsaVerificationResult
            {
                IsValid = true,
                Key = key,
                Payload = payload
            };
        }

        internal static RsaVerificationResult Invalid(string? key, string error)
        {
            return new RsaVerificationResult
            {
                IsValid = false,
                Key = key,
                Error = error
            };
        }
    }
}
