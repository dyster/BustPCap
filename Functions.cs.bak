using System;
using System.Collections.Generic;
using System.Text;

namespace BustPCap
{
    class Functions
    {
        /// <summary>
        /// Converts a DateTime to Unix Epoc (seconds since 1970)
        /// </summary>
        /// <param name="time"></param>
        /// <returns></returns>
        public static uint DateTimeToUnixEpoch(DateTime time)
        {
            var unixepoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            TimeSpan timeSpan = time.Subtract(unixepoch);
            return (uint)timeSpan.TotalSeconds;
        }
    }
}
