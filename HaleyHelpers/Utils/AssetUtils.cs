using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management;
using System.IO;
using System.Reflection;
using Haley.Enums;
using System.Security.Principal;
using System.Runtime.InteropServices;
using Haley.Models;
using System.Runtime.CompilerServices;

//List<(string query, string scope)> queryTuple = new List<(string query, string scope)>();
//queryTuple.Add(("select * from win32_bios", string.Empty));
//queryTuple.Add(("select * from win32_baseboard", string.Empty));
////queryTuple.Add(("select * from Win32_LogicalDisk", string.Empty));
////queryTuple.Add(("select * from Win32_physicalmedia", string.Empty));
////queryTuple.Add(("select * from Win32_diskdrive", string.Empty));
////queryTuple.Add(("select * from Win32_PhysicalMemory", string.Empty));
////queryTuple.Add(("select * from Win32_desktopmonitor", string.Empty));
////queryTuple.Add(("select * from Win32_ComputerSystem", string.Empty));
////queryTuple.Add(("select * from Win32_operatingsystem", string.Empty));
//queryTuple.Add(("select * from Win32_Keyboard", "root\\cimv2"));
//queryTuple.Add(("select * from Win32_SoundDevice", "root\\cimv2"));
//queryTuple.Add(("select * from Win32_LogonSession", "root\\cimv2"));
//queryTuple.Add(("select * from Win32_PointingDevice", "root\\cimv2"));
//queryTuple.Add(("select * from WmiMonitorID", "root\\wmi"));
////queryTuple.Add(("select * from WmiMonitorBasicParams", "root\\wmi"));


////Get - WmiObject - Class Win32_BIOS
////    Get-WmiObject -Class Win32_ComputerSystem
////    Get-WmiObject -Class Win32_OperatingSystem
////    Get-WmiObject -Class Win32_NetworkAdapter
////    Get-WmiObject -Class Win32_NetworkAdapterConfiguration
////    Get-WmiObject -Class Win32_Product

namespace Haley.Utils
{
    public static partial class AssetUtils
    {
        static (AssetType type,string prop) GetAssetInfo (AssetIdentifier target) {
            switch (target) {
                case AssetIdentifier.MotherBoardID:
                return (AssetType.MotherBoard, "SerialNumber");
                case AssetIdentifier.ProcessorID:
                return (AssetType.Processor, "ProcessorId");
                case AssetIdentifier.ComputerUserName:
                return (AssetType.Computer, "UserName");
                case AssetIdentifier.BIOSID:
                return (AssetType.BIOS, "SerialNumber");
            }
            throw new NotImplementedException();
        }

        public static string GetUserSID(string userName) {
            try {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux)) return string.Empty;
                NTAccount ntAccount = new NTAccount(userName);
                SecurityIdentifier sid = (SecurityIdentifier)ntAccount.Translate(typeof(SecurityIdentifier));
                return sid.Value;
            } catch (Exception ex) {
                throw;
            }
        }

        public static List<Dictionary<string, object>> GetProperties(AssetType target, params object[] propFilter) {
            return GetPropertiesEx(target, null, false, propFilter);
        }

        public static List<Dictionary<string, object>> GetPropertiesEx(AssetType target, string queryFilter, params object[] propFilter) {
            return GetPropertiesEx(target, queryFilter, false, propFilter);
        }

        public static List<Dictionary<string, object>>  GetPropertiesEx(AssetType target, string queryFilter, bool shortToString, params object[] propFilter) {
            var qry = $@"select * from {target.GetDescription()}";
            if (!string.IsNullOrWhiteSpace(queryFilter)) {
                qry += " " + $@"where {queryFilter}";
            }
            var scope = target.GetAttributeValue<ScopeAttribute>();
            return GetProperties(qry,scope, shortToString,propFilter);
        }

        public static List<Dictionary<string, object>> GetProperties(string query, string scope, bool shortToString, params object[] propFilter) {
            return GetPropertiesInternal(query, scope, shortToString, propFilter);
        }

        static List<Dictionary<string, object>> GetPropertiesInternal(string query, string scope, bool shortToString, params object[] propFilter) {
            try {
                List<Dictionary<string, object>> result = new List<Dictionary<string, object>>();
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux)) return result;
                var mo_searcher = new ManagementObjectSearcher(query);
                if (!string.IsNullOrWhiteSpace(scope)) mo_searcher.Scope = new ManagementScope(scope);
                foreach (var mo in mo_searcher.Get()) {
                    Dictionary<string, object> localRes = new Dictionary<string, object>();
                    if (propFilter != null && propFilter.Length > 0) {
                        foreach (var prop in propFilter) {
                            try {
                                if (prop == null) continue;
                                object value = null;
                                string propKey = null;
                                bool ToSize = false;
                                if (prop is string propStr) {
                                    propKey = propStr;
                                } else if (prop is ValueTuple<string,bool> propTup) {
                                    propKey = propTup.Item1;
                                    ToSize = propTup.Item2;
                                } else {
                                    continue;
                                }
                                    value = mo[propKey];
                                if (ToSize && Double.TryParse(value.ToString(),out var res)) {
                                    value = res.ToFileSize();
                                }
                                if (shortToString && value is short[] valShort) value = valShort.Convert();
                                localRes.Add(propKey, value);
                            } catch (Exception) {
                                continue;
                            }
                        }
                    } else {
                        foreach (var moProp in mo.Properties) {
                            try {
                                var value = moProp.Value;
                                if (shortToString && value is short[] valShort) value = valShort.Convert();
                                localRes.Add(moProp.Name, value);
                            } catch (Exception) {
                                continue;
                            }
                        }
                    }
                    result.Add(localRes);
                }
                return result;
            } catch (Exception ex) {
                throw new Exception($@"Error while processing query : {query} for scope {scope}. {Environment.NewLine}. {ex.Message}");
            }
        }

        public static string GetUserFullName(string userName = null) {
            return GetUserAccountInternal(userName, "FullName")?.Values?.First()?.ToString();
        }

        public static Dictionary<string,object> GetUserAccount(string userName = null) {
            return GetUserAccountInternal(userName);
        }

        static Dictionary<string, object> GetUserAccountInternal(string userName, params object[] propFilter) {
            try {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux)) return null;
                if (string.IsNullOrWhiteSpace(userName)) userName = GetId(AssetIdentifier.ComputerUserName);
                var results = AssetUtils.GetPropertiesEx(AssetType.UserAccount, queryFilter: $@"Name = '{userName.Split('\\').Last()}'", propFilter);
                return results.First();
            } catch (Exception) {
                return null;
            }
        }

        public static string GetId(AssetIdentifier target)
        {
            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux)) return string.Empty;
                var info = GetAssetInfo(target);
                //If we are trying to get Full name, we first need to get the SID of the user and then the FullName
                var propResult = GetPropertiesEx(info.type, null, false, info.prop);
                return propResult.First()?.Values?.First()?.ToString() ?? null;
            } catch (Exception) {
                throw;
            }
        }

        public static string GetMachineId()
        {
            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux)) return string.Empty;
                return (GetId(AssetIdentifier.MotherBoardID) + "###" +GetId(AssetIdentifier.ProcessorID));
            }
            catch (Exception)
            {
                throw;
            }
        }

    }
}
