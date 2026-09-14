using Haley.Models;
using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Haley.Internal
{
    internal sealed class MachineFingerprintJsonConverter : JsonConverter<MachineFingerprint>
    {
        public override MachineFingerprint Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType == JsonTokenType.String)
            {
                return new MachineFingerprint { Fingerprint = reader.GetString() ?? string.Empty };
            }

            if (reader.TokenType != JsonTokenType.StartObject)
                throw new JsonException("Machine proof must be an opaque string.");

            using (var document = JsonDocument.ParseValue(ref reader))
            {
                var root = document.RootElement;
                return new MachineFingerprint
                {
                    Source = root.TryGetProperty("source", out var source) ? source.GetString() ?? string.Empty : string.Empty,
                    Fingerprint = root.TryGetProperty("fingerprint", out var fingerprint) ? fingerprint.GetString() ?? string.Empty : string.Empty
                };
            }
        }

        public override void Write(Utf8JsonWriter writer, MachineFingerprint value, JsonSerializerOptions options)
        {
            writer.WriteStringValue(value.Fingerprint);
        }
    }
}
