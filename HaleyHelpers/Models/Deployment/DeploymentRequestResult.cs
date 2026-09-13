namespace Haley.Models
{
    public sealed class DeploymentRequestResult
    {
        public bool IsValid { get; internal set; }
        public string? Error { get; internal set; }
        public string? Message { get; internal set; }
        public string? Envelope { get; internal set; }
        public string? RequestPath { get; internal set; }
        public DeploymentRequest? Request { get; internal set; }
    }
}
