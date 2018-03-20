using System;
using System.Linq;

namespace AdderBot
{
    public static class Adder
    {
        // This bot treats the input string as a space-separated list of integers
        // The output is the sum of these integers
        public static string Process(string input)
        {
            try
            {
                var values = input.Split(' ');
                var sum = values.Select(v => Int32.Parse(v)).Aggregate((a, b) => a + b).ToString();
                return sum;
            }
            catch
            {
                return "error";
            }
        }
    }
}