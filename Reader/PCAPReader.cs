using System;
using System.IO;

namespace BustPCap
{
    /// <summary>
    /// The base version of the Reader, does not work on its own
    /// </summary>
    public class PCAPReader
    {
        /// <summary>
        /// Examines a file to see if it is in PCAP format
        /// </summary>
        /// <param name="path"></param>
        /// <returns></returns>
        public static bool CanRead(string path)
        {
            using (FileStream stream = File.OpenRead(path))
            {
                return CanRead(stream);
            }
        }

        /// <summary>
        /// Examines a stream to see if the start matches the pcap format, does not set Position back!
        /// </summary>
        /// <param name="stream">The Stream to examine</param>
        /// <returns>True if in PCAP format</returns>
        public static bool CanRead(Stream stream)
        {
            var bytes = new byte[4];

            stream.Read(bytes, 0, 4);


            return bytes[0] == 0xd4 && bytes[1] == 0xc3 && bytes[2] == 0xb2 && bytes[3] == 0xa1 || bytes[0] == 0xa1 &&
                bytes[1] == 0xb2 && bytes[2] == 0xc3 && bytes[3] == 0xd4;
        }

        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }

        public int Count { get; set; }

        protected void Process(PCAPBlock block)
        {
            if (StartTime == default)
                StartTime = block.DateTime;
            else if (block.DateTime < StartTime)
                StartTime = block.DateTime;

            if (EndTime == default)
                EndTime = block.DateTime;
            else if (block.DateTime > EndTime)
                EndTime = block.DateTime;

            Count++;
        }
    }
}
