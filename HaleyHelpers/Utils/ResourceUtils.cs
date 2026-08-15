using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management;
using System.IO;
using System.Reflection;
using Microsoft.Extensions.Configuration;
using Haley.Abstractions;
using Haley.Models;

namespace Haley.Utils {
    public static class ResourceUtils {

        public static IFeedback FetchVariable(params string[] name) {
            return FetchVariableWith(null, name);
        }

        public static bool TryFetchVariable<T>(ref T result, params string[] name) {
            try {
                var fetched = FetchVariable(name);
                if (fetched == null || !fetched.Status || fetched.Result == null) return false;

                var fb = fetched.Result.TryAs<T>();
                if (!fb.Status) return false;

                result = fb.Result;
                return true;
            } catch (Exception) {
                return false;
            }
        }

        public static bool IsDevelopment =>
                 string.Equals(Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT"), "Development", StringComparison.OrdinalIgnoreCase);

        public static IFeedback FetchVariableWith(IConfiguration cfg, params string[] name) {
            if (name.Length < 1) return new Feedback(false, "No variable name provided");
            object value = null;

            // 1. Preference to Environment variables
            foreach (var key in name) {
                value = Environment.GetEnvironmentVariable(key, EnvironmentVariableTarget.User); // Windows user variables
                if (value == null) value = Environment.GetEnvironmentVariable(key);              // Cross-platform system variables
                if (value != null && !string.IsNullOrWhiteSpace(Convert.ToString(value)) && value.ToString() != "\"\"")
                    return new Feedback(true).SetResult(value);
            }

            // 2. Appsettings.json
            if (cfg == null) cfg = GenerateConfigurationRoot(); // attempt to generate, but not a failure if still null

            if (cfg != null) {
                foreach (var key in name) {
                    value = cfg[key];
                    if (value != null && !string.IsNullOrWhiteSpace(Convert.ToString(value)))
                        return new Feedback(true).SetResult(value);
                }
            }

            // Value not found — not a failure, caller decides what to do with absence
            return new Feedback(true).SetMessage("Operation completed. No value found.");
        }

        public static List<Dictionary<string, object>> AsDictionaryList(this IConfigurationSection section, char delimiter = ';') {
            if (section == null) return null;
            var result = new List<Dictionary<string, object>>();
            foreach (var child in section.GetChildren()) {
                if (child == null || string.IsNullOrWhiteSpace(child.Key)) continue; //skip empty children
                var dic = new Dictionary<string, object>();

                //Straight children with values.
                if (child.Value != null && !string.IsNullOrWhiteSpace(child.Value)) {
                    //If the child has a value, then we can add it directly.
                    if (child.Value.TryDictionarySplit(out var valueDic, delimiter)) {
                        dic.Add(child.Key, valueDic);
                    } else {
                        dic.Add(child.Key, child.Value);
                    }
                    result.Add(dic);
                    continue; //skip to next child
                }

                //A child could contain a plain value or a json string or a section.
                foreach (var grandChild in child.GetChildren()) {
                    if (grandChild.Value == null) {
                        dic[grandChild.Key] = AsDictionaryList(grandChild);
                    } else {
                        dic[grandChild.Key] = grandChild.Value;
                    }
                }
                result.Add(dic);
            }
            return result;
        }

        public static string[] GetResourceNames(Assembly assembly_name = null) {
            if (assembly_name == null) {
                assembly_name = Assembly.GetCallingAssembly();
            }
            return assembly_name.GetManifestResourceNames();
        }

        public static bool DownloadEmbeddedResource(string resource_name, string save_dir_path, string save_file_name, Assembly assembly_name = null) {
            try {
                if (assembly_name == null) assembly_name = Assembly.GetCallingAssembly();
                if (save_file_name == null) save_file_name = resource_name; //use same resource name as target name
                string full_file_path = Path.Combine(save_dir_path, save_file_name);
                return DownloadEmbeddedResource(resource_name, full_file_path, assembly_name);
            } catch (Exception) {
                throw;
            }
        }
        public static bool DownloadEmbeddedResource(string resource_name, string save_file_path, Assembly assembly_name = null) {
            try {
                if (assembly_name == null) assembly_name = Assembly.GetCallingAssembly();
                var _streambyte = GetEmbeddedResource(resource_name, assembly_name);
                File.WriteAllBytes(save_file_path, _streambyte);
                return true;
            } catch (Exception) {
                throw;
            }
        }
        public static byte[] GetEmbeddedResource(string full_resource_name, Assembly assembly = null) {
            try {
                if (assembly == null) assembly = Assembly.GetCallingAssembly();
                var _stream = assembly.GetManifestResourceStream(full_resource_name); //Get the resource from the assembly
                if (_stream == null) return null;

                byte[] _stream_byte = new byte[_stream.Length]; //initiate a byte array
                using (var memstream = new MemoryStream()) {
                    _stream.CopyTo(memstream);
                    _stream_byte = memstream.ToArray();
                }

                return _stream_byte;
            } catch (Exception ex) {
                throw ex;
            }
        }

        public static IConfigurationRoot GenerateConfigurationRoot(string[] jsonPaths = null, string basePath = null) {
            var builder = new ConfigurationBuilder();
            var jsonlist = jsonPaths?.ToList() ?? new List<string>();
            if (basePath == null) basePath = AssemblyUtils.GetBaseDirectory(); ; //Hopefully both interface DLL and the main app dll are in same directory where the json files are present.
            builder.SetBasePath(basePath); // let us load the file from a specific directory

            if (jsonlist == null || jsonlist.Count < 1) {
                jsonlist = new List<string>() { "appsettings", "connections" }; //add these two default jsons.
            }

            if (!jsonlist.Contains("appsettings")) jsonlist.Add("appsettings");
            if (!jsonlist.Contains("connections")) jsonlist.Add("connections");

            foreach (var path in jsonlist) {
                if (path == null) continue;
                string finalFilePath = path.Trim();
                if (!finalFilePath.EndsWith(".json", StringComparison.OrdinalIgnoreCase) && finalFilePath != null) {
                    finalFilePath += ".json";
                }

                //Assume it is an absolute path
                if (!File.Exists(finalFilePath)) {
                    //We assumed it was an abolute path and it doesn't exists.. What if it is a relative path?
                    //Combine with base path and check if it exists.
                    if (!File.Exists(Path.Combine(basePath, finalFilePath))) continue;
                }
                //If we reach here then the file is present, regardless of whether it is absolute or relative.

                builder.AddJsonFile(finalFilePath);
            }

            // Environment variables are added after JSON so they have higher precedence.
            // The provider also maps double underscores to section delimiters, for example:
            // Kida__Admin__PasswordHash -> Kida:Admin:PasswordHash.
            builder.AddEnvironmentVariables();
            return builder.Build();
        }
    }
}
