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
The product supplies only its identity and the feature/limit catalog it actually
understands:

```csharp
using Haley.Models;
using Haley.Utils;

var request = DeploymentUtils.PrepareRequest(new DeploymentRequestInput
{
    Product = "sample.product",
    ProductVersion = "1.4.0",
    Deployment = "customer-primary",
    Features = new[] { "documents.read", "documents.write" },
    AvailableLimits = new[] { "tenant.max" },
    MachineEvidenceMode = MachineLockMode.Lite,
    BaseDirectory = AppContext.BaseDirectory
});

var result = DeploymentUtils.EvaluateGrant(new DeploymentGrantOptions
{
    LicensePath = "license/sample.lic",
    Product = "sample.product",
    ProductVersion = "1.4.0",
    Deployment = "customer-primary",
    Features = new[] { "documents.read", "documents.write" },
    AvailableLimits = new[] { "tenant.max" },
    TrialLimits = new Dictionary<string, long> { ["tenant.max"] = 1 },
    RequestMachineEvidenceMode = MachineLockMode.Lite,
    TrialDays = 14,
    BaseDirectory = AppContext.BaseDirectory
});
```

The first call creates `deployinfo/deploy.pem`, `deploy.pub`, and `request.json`.
Persist that directory and send only `request.json` to the issuer. Private deployment
keys and raw machine identifiers never leave the deployment; only domain-separated
SHA-256 fingerprints appear in the request. An unchanged catalog reuses the existing
signed request byte-for-byte; a version, catalog, or evidence change refreshes it while
preserving the deployment identity. `None`, `Lite`, and `Strong` machine modes
are supported. Signed features are intersected with the local catalog, numeric limits
use `string` keys and `long` values, and the verified result is suitable for caching by
the consuming application.
