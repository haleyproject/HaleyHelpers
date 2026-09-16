using System;

namespace Haley.Models
{
    /// <summary>Non-configurable safety ceilings applied by the shared licensing runtime and issuer tooling.</summary>
    public static class LicensePolicyLimits
    {
        public const int MaximumTrialDays = 90;
        public const int MaximumGraceDays = 45;

        public static int CapTrialDays(int value) => Math.Min(value, MaximumTrialDays);

        public static int CapGraceDays(int value) => Math.Min(value, MaximumGraceDays);
    }
}
