using System;
using System.Collections.Generic;

namespace Haley.Models
{
    /// <summary>
    /// What a product supplies to load its license. The product identity, version, feature catalog and limit catalog
    /// are read from <c>appinfo.json</c>; the compiled catalogs, when given, must match that file exactly.
    /// </summary>
    public sealed class LicenseRuntimeOptions
    {
        /// <summary>Product code, such as <c>plaintrack</c>. Must equal the product in <c>appinfo.json</c>.</summary>
        public string Product { get; set; } = string.Empty;

        /// <summary>Feature codes compiled into the product. When set, <c>appinfo.json</c> must advertise exactly these.</summary>
        public IReadOnlyCollection<string>? Features { get; set; }

        /// <summary>Limit codes compiled into the product. When set, <c>appinfo.json</c> must advertise exactly these.</summary>
        public IReadOnlyCollection<string>? Limits { get; set; }

        /// <summary>Application base directory. Defaults to <see cref="AppContext.BaseDirectory"/>.</summary>
        public string? BaseDirectory { get; set; }

        /// <summary>Path to <c>appinfo.json</c>. Defaults to <c>appinfo.json</c> in the base directory.</summary>
        public string? ApplicationInfoPath { get; set; }

        /// <summary>The top-level <c>deployinfo-location</c> setting. Empty uses <c>&lt;base&gt;/.deployinfo</c>.</summary>
        public string? DeploymentInfoLocation { get; set; }

        /// <summary>License artifact path. Empty uses <c>license.lic</c> in the deployment-information directory.</summary>
        public string? LicensePath { get; set; }

        /// <summary>Issuer public key path. Empty uses Haley's trusted key registry.</summary>
        public string? PublicKeyPath { get; set; }

        public int TrialDays { get; set; } = 14;
        public int ExpiringDays { get; set; } = 30;
        public int RecoveryDays { get; set; } = 7;

        /// <summary>Current UTC time. Defaults to the system clock.</summary>
        public Func<DateTimeOffset>? Clock { get; set; }
    }
}
