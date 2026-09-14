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

namespace Haley.Utils
{
    public static class ConsoleUtils
    {
        static ConsoleKey[] confirmationKeys = { ConsoleKey.Y, ConsoleKey.N, ConsoleKey.Enter };
        public static void AddLine(int count = 1) {
            for (int i = 0; i < count; i++) {
                Console.WriteLine();
            }
        }

        public static bool GetUserConfirmation(string message, ConsoleKey defaultKey = ConsoleKey.Y) {
            bool result = false;
            AddLine();
            //Console.WriteLine("*".PadCenter(padLength, '*'));
            while (true) {
                AddLine();
                Console.WriteLine(message);
                var key = Console.ReadKey();
                AddLine();
                if (!confirmationKeys.Contains(key.Key)) {
                    Console.WriteLine(@"Wrong input. Accepted Inputs are 'Y', 'N', 'Enter'. Please try again.");
                    continue;
                }

                if (key.Key == ConsoleKey.Enter) {
                    result = defaultKey == ConsoleKey.Y; //When user presses 'Enter', we just check if the default is Y or N
                } else {
                    result = key.Key == ConsoleKey.Y;
                }
                break;
            }
            return result;
        }

        public static int GetUserValue(string message, int defaultValue = 1, int[] possibleValues = null) {
            int result = defaultValue;
            //Console.WriteLine("*".PadCenter(padLength, '*'));
            bool exitFlag = false;
            while (!exitFlag) {
                AddLine();
                Console.WriteLine(message);
                List<ConsoleKeyInfo> userInput = new List<ConsoleKeyInfo>();
                while (true) {
                    var key = Console.ReadKey();
                    if (key.Key == ConsoleKey.Enter) break;
                    userInput.Add(key);
                }

                //User directly clicked Enter
                if (userInput.Count == 0) {
                    result = defaultValue;
                    break;
                }

                var chars = userInput.Select(p => p.KeyChar).ToArray();
                //User has some manual value
                if (int.TryParse(new string(chars), out var res)) {
                    result = res;
                    exitFlag = true;
                }

                if (possibleValues != null && possibleValues.Count() > 0) {
                    if (!possibleValues.Contains(result)) {
                        Console.WriteLine("Invalid input provided. Please try again.");
                        continue;
                    }
                }

                if (exitFlag) break;


                //Until this point if we have everything successfull, we proceed.
                Console.WriteLine(@"Wrong input. Only Numeric Values are accepted. Please try again.");
            }
            return result;
        }

        public static long GetUserLongValue(string message, long defaultValue = 0, long minimum = 0, long maximum = long.MaxValue) {
            while (true) {
                AddLine();
                Console.WriteLine(message);
                var value = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(value)) return defaultValue;
                if (long.TryParse(value.Trim(), out var result) && result >= minimum && result <= maximum) {
                    return result;
                }
                Console.WriteLine($"Invalid input. Enter a whole number from {minimum} to {maximum}.");
            }
        }
    }
}
