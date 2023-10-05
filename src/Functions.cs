using System;
using System.Collections.Generic;

namespace BustPCap
{
    internal static class Functions
    {
        /// <summary>
        /// Converts a DateTime to Unix Epoc (seconds since 1970)
        /// </summary>
        /// <param name="time"></param>
        /// <returns></returns>
        public static uint DateTimeToUnixEpoch(DateTime time)
        {
            var unixepoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var timeSpan = time.Subtract(unixepoch);
            return (uint)timeSpan.TotalSeconds;
        }

        public static string SerializeClassToJSON(object o)
        {
            var props = o.GetType().GetProperties();
            var list = new List<string>();

            foreach (var prop in props)
            {
                var thevalue = prop.GetValue(o, null);
                if (thevalue != null)
                {
                    var thevaluestring = thevalue.ToString();
                    thevaluestring = thevaluestring.Replace('\\', '/');
                    thevaluestring = thevaluestring.Replace("\"", "\\\"");
                    list.Add('"' + prop.Name + "\": \"" + thevaluestring + '"'); 
                }
                else
                    list.Add('"' + prop.Name + "\": \"null\"");
            }
            var json = "{ " + string.Join(",", list) + " }";

            return json;
        }
    }
}