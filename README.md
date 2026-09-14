# Haley.Helpers
Some of the common C# Helpers

## QR codes

`QrCodeBuilder` creates cross-platform QR codes from any text or URL. SVG is suitable
for web pages and printing; PNG bytes are suitable for files and HTTP responses.

```csharp
using Haley.Utils;
using System.Text.Json;

var svg = QrCodeBuilder.CreateSvg("https://example.com/view/signed-token");
var png = QrCodeBuilder.CreatePng("https://example.com/view/signed-token");
```

## Deployment requests and signed grants

`DeploymentUtils` provides the reusable, product-neutral deployment-grant workflow.
The request producer supplies only the product, version, and available feature catalog.
Deployment identity and available machine evidence are generated locally:

```csharp
using Haley.Models;
using Haley.Utils;

var request = DeploymentUtils.EnsureRequest(new DeploymentRequestInput
{
    Product = "sample.product",
    ProductVersion = "1.4.0",
    Features = new[] { "documents.read", "documents.write" },
    Limits = new Dictionary<string, DeploymentLimitDefinition>
    {
        ["tenant.max"] = new DeploymentLimitDefinition
        {
            DefaultValue = JsonSerializer.SerializeToElement(5L),
            Description = "Maximum active tenants"
        },
        ["edition"] = new DeploymentLimitDefinition
        {
            DefaultValue = JsonSerializer.SerializeToElement("standard"),
            Description = "Configured product edition"
        }
    },
    BaseDirectory = AppContext.BaseDirectory,
    LicensePath = ""
});

var result = DeploymentUtils.EvaluateGrant(new DeploymentGrantOptions
{
    LicensePath = "",
    Product = "sample.product",
    ProductVersion = "1.4.0",
    Features = request.Request!.Features,
    Limits = request.Request.Limits,
    TrialLimits = new Dictionary<string, JsonElement>
    {
        ["tenant.max"] = JsonSerializer.SerializeToElement(1L),
        ["edition"] = JsonSerializer.SerializeToElement("trial")
    },
    TrialDays = 14,
    BaseDirectory = AppContext.BaseDirectory
});
```

`EnsureRequest` is the normal application-startup operation. It creates
`.deployinfo/deploy.pem`, `deploy.pub`, `deployment.json`, and
`sample.product.request`. Persist that directory and send only the `.request` file to the issuer. Private deployment
keys and raw machine identifiers never leave the deployment; only domain-separated
SHA-256 fingerprints appear only under a generic `proof` object as opaque arrays in the request. Hardware source names are
not serialized. When the request format, application version, or advertised catalog
changes, `EnsureRequest` renews the request while preserving the random deployment ID
and keypair. When only the keypair remains, `EnsureRequest` may create a new identity and
request only when the resolved license path contains no artifact. If a license exists,
the incomplete state fails closed so an issued deployment binding is not replaced.
Corrupt or mismatched deployment state is never silently replaced.
`PrepareRequest` and `RenewRequest` remain available to operator tooling. The issuer alone
selects `None`, `Lite`, or `Strong`, feature decisions, opaque limit values, validity, and grace.
`EvaluateGrant` never creates an identity or request. An empty license path resolves to
`.deployinfo/license.lic`; a non-empty path is authoritative.

Each product version advertises the limit keys it understands, a short description, and
a suggested default. A primitive default also declares the value type: boolean,
non-negative whole number, or string. The default is guidance for the issuer, not an
automatic entitlement. Issuance must choose one correctly typed value for every
advertised key. Haley signs and transports those values without interpreting their
product meaning; the target consumes only keys in its own catalog and ignores unknown
signed limits from another or newer product version.
