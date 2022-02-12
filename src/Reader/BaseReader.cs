using System;
using System.IO;

namespace BustPCap
{
    /// <summary>
    /// The base version of the Reader, does not work on its own
    /// </summary>
    public class BaseReader
    {
        /// <summary>
        /// Examines a file to see if it is in PCAP format
        /// </summary>
        /// <param name="path"></param>
        /// <returns></returns>
        public static Format CanRead(string path)
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
        public static Format CanRead(Stream stream)
        {
            var bytes = new byte[4];

            stream.Read(bytes, 0, 4);

            if (IsPCAPNG(bytes))
                return Format.PCAPNG;
            else if (IsPCAP(bytes))
                return Format.PCAP;
            else
                return Format.NOPE;            
        }

        public static bool IsPCAP(byte[] bytes)
        {
            return bytes[0] == 0xd4 && bytes[1] == 0xc3 && bytes[2] == 0xb2 && bytes[3] == 0xa1 || bytes[0] == 0xa1 &&
                bytes[1] == 0xb2 && bytes[2] == 0xc3 && bytes[3] == 0xd4;
        }

        public static bool IsPCAPNG(byte[] bytes)
        {
            return bytes[0] == '\n' && bytes[1] == '\r' && bytes[2] == '\r' && bytes[3] == '\n';
        }

        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }

        public int Count { get; set; }

        protected void Process(IBlock block)
        {
            if(block.DateTime == default)
            {
                return;
            }

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

    public enum Format
    {
        NOPE,
        PCAP,
        PCAPNG
    }
}
