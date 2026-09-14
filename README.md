# Haley.Helpers
Some of the common C# Helpers

## QR codes

`QrCodeBuilder` creates cross-platform QR codes from any text or URL. SVG is suitable
for web pages and printing; PNG bytes are suitable for files and HTTP responses.

```csharp
using Haley.Utils;

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

var request = DeploymentUtils.PrepareRequest(new DeploymentRequestInput
{
    Product = "sample.product",
    ProductVersion = "1.4.0",
    Features = new[] { "documents.read", "documents.write" },
    BaseDirectory = AppContext.BaseDirectory
});

var result = DeploymentUtils.EvaluateGrant(new DeploymentGrantOptions
{
    LicensePath = "",
    Product = "sample.product",
    ProductVersion = "1.4.0",
    Features = new[] { "documents.read", "documents.write" },
    AvailableLimits = new[] { "tenant.max" },
    TrialLimits = new Dictionary<string, long> { ["tenant.max"] = 1 },
    TrialDays = 14,
    BaseDirectory = AppContext.BaseDirectory
});
```

The first call creates `.deployinfo/deploy.pem`, `deploy.pub`, `deployment.json`, and
`sample.product.request`. Persist that directory and send only the `.request` file to the issuer. Private deployment
keys and raw machine identifiers never leave the deployment; only domain-separated
SHA-256 fingerprints appear in the request. `RenewRequest` refreshes version, catalog,
and evidence while preserving the random deployment ID and keypair. The issuer alone
selects `None`, `Lite`, or `Strong`, feature decisions, numeric limits, validity, and grace.
`EvaluateGrant` never creates an identity or request. An empty license path resolves to
`.deployinfo/license.lic`; a non-empty path is authoritative.
