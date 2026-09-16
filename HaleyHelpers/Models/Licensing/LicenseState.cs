namespace Haley.Models
{
    /// <summary>
    /// Effective license state at a moment in time. Time-based transitions (expiring, grace, expiry and the end of a
    /// trial or recovery window) are resolved from the verified grant against the caller's clock.
    /// </summary>
    public enum LicenseState
    {
        Invalid = 0,
        Trial = 1,
        TrialExpired = 2,
        NotYetValid = 3,
        Valid = 4,
        Expiring = 5,
        Grace = 6,
        Recovery = 7,
        Expired = 8,
        /// <summary>Enforcement is deliberately off for this deployment (a hardcoded glass break). No grant was read.</summary>
        GlassBreak = 9
    }
}
