using System.Text.Json;
using System.Text.Json.Serialization;

namespace Haley.Internal
{
    internal static class DeploymentJson
    {
        internal static JsonSerializerOptions Options { get; } = Create(writeIndented: true);

        internal static JsonSerializerOptions CompactOptions { get; } = Create(writeIndented: false);

        private static JsonSerializerOptions Create(bool writeIndented)
        {
            var result = new JsonSerializerOptions(JsonSerializerDefaults.Web)
            {
                PropertyNameCaseInsensitive = false,
                WriteIndented = writeIndented
            };
            result.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase));
            return result;
        }
    }
}
