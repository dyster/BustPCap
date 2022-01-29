using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace BustPCap
{
    public class PCAPNGBlock : IBlock
    {
        private readonly int _bytelength;

        public PCAPNGBlock(byte[] bytes, bool normalByteOrder)
        {
            if (normalByteOrder)
                Header = (PCAPNGHeader)BitConverter.ToInt32(bytes, 0);
            else
                Header = (PCAPNGHeader)BitConverter.ToInt32(new byte[] { bytes[3], bytes[2], bytes[1], bytes[0] }, 0);
            _bytelength = bytes.Length;
        }

        public PCAPNGHeader Header { get; }

        public DateTime DateTime { get; set; }

        public byte[] PayLoad { get; set; }

        public uint OriginalLength { get; set; }

        public int PayloadLength => PayLoad.Length;

        //public DateTime Timestamp { get; internal set; }
        public ushort LinkLayerType { get; internal set; }

        public override string ToString()
        {
            return Header + " [" + _bytelength + " bytes]";
        }

        public static ulong GetUInt64(byte[] data, bool byteorder, int startIndex)
        {
            if (byteorder)
            {
                return BitConverter.ToUInt64(data, startIndex);
            }
            else
            {
                var readbytes = new byte[8];
                Array.Copy(data, startIndex, readbytes, 0, 4);
                readbytes = readbytes.Reverse().ToArray();
                return BitConverter.ToUInt64(readbytes, 0);
            }
        }

        public static uint GetUInt32(byte[] data, bool byteorder, int startIndex)
        {
            if (byteorder)
            {
                return BitConverter.ToUInt32(data, startIndex);
            }
            else
            {
                var readbytes = new byte[4];
                Array.Copy(data, startIndex, readbytes, 0, 4);
                return BitConverter.ToUInt32(new byte[] { readbytes[3], readbytes[2], readbytes[1], readbytes[0] }, 0);
            }
        }

        public static ushort GetUInt16(byte[] data, bool byteorder, int startIndex)
        {
            if (byteorder)
            {
                return BitConverter.ToUInt16(data, startIndex);
            }
            else
            {
                var readbytes = new byte[2];
                Array.Copy(data, startIndex, readbytes, 0, 2);
                return BitConverter.ToUInt16(new byte[] { readbytes[1], readbytes[0] }, 0);
            }
        }        
    }

    public enum PCAPNGHeader
    {
        SectionHeader = 168627466,
        Reserved = 0x00000000,
        InterfaceDescription = 0x00000001,
        Packet = 0x00000002,
        SimplePacket = 0x00000003,
        NameResolution = 0x00000004,
        InterfaceStatistics = 0x00000005,
        EnhancedPacket = 0x00000006,
        IRIGTimeStamp = 0x00000007,
        Arinc = 0x00000008
    }

    public class InterfaceDescription
    {
        public InterfaceDescription(byte[] bytes, bool normalByteOrder)
        {
            LinkLayerType = PCAPNGBlock.GetUInt16(bytes, normalByteOrder, 0);
            SnapLen = PCAPNGBlock.GetUInt32(bytes, normalByteOrder, 4);

            var options = new byte[bytes.Length - 8];
            Array.Copy(bytes, 8, options, 0, options.Length);
            int pointer = 0;
            while (pointer < options.Length)
            {
                var optionCode = PCAPNGBlock.GetUInt16(options, normalByteOrder, pointer);
                pointer += 2;
                var optionLen = PCAPNGBlock.GetUInt16(options, normalByteOrder, pointer);
                pointer += 2;
                if (optionCode == 0x00 && optionLen == 0x00)
                    break;
                switch (optionCode)
                {
                    case 1:
                        //TODO reverse byte order for these when needed
                        var s = Encoding.UTF8.GetString(options, pointer, optionLen);
                        pointer += optionLen;
                        Comments.Add(s);
                        break;
                    case 2:
                        Name = Encoding.UTF8.GetString(options, pointer, optionLen);
                        pointer += optionLen;
                        break;
                    case 3:
                        Description = Encoding.UTF8.GetString(options, pointer, optionLen);
                        pointer += optionLen;
                        break;
                    case 4:
                        if (normalByteOrder)
                        {
                            IPv4 = new IPAddress(new[]
                            {options[pointer], options[pointer + 1], options[pointer + 2], options[pointer + 3]});
                            pointer += 4;
                            IPv4SubNet = new IPAddress(new[]
                                {options[pointer], options[pointer + 1], options[pointer + 2], options[pointer + 3]});
                            pointer += 4;
                        }
                        else
                        {
                            IPv4 = new IPAddress(new[]
                            {options[pointer+3], options[pointer + 2], options[pointer + 1], options[pointer]});
                            pointer += 4;
                            IPv4SubNet = new IPAddress(new[]
                                {options[pointer+3], options[pointer + 2], options[pointer + 1], options[pointer]});
                            pointer += 4;
                        }
                        break;
                    case 5:
                        // no ipv6 thank you very much
                        pointer += 17;
                        break;
                    case 6:
                        if (normalByteOrder)
                        {
                            MAC = new[]
                            {
                                options[pointer], options[pointer + 1], options[pointer + 2], options[pointer + 3],
                                options[pointer + 4], options[pointer + 5]
                            };
                        }
                        else
                        {
                            MAC = new[]
                            {
                                options[pointer+5], options[pointer + 4], options[pointer + 3], options[pointer + 2],
                                options[pointer + 1], options[pointer]
                            };
                        }

                        pointer += 6;
                        break;
                    case 7:
                        // no idea what this option is
                        pointer += 8;
                        break;
                    case 8:
                        BitsPerSecond = PCAPNGBlock.GetUInt64(options, normalByteOrder, pointer);
                        pointer += 8;
                        break;
                    case 9:
                        TimeStampResolution = Convert.ToInt16((sbyte)options[pointer]);
                        pointer++;
                        break;
                    case 10:
                        TimeZone = PCAPNGBlock.GetUInt32(options, normalByteOrder, pointer);
                        pointer += 4;
                        break;
                    case 11: //TODO reverse order when needed
                        OS = Encoding.UTF8.GetString(options, pointer, optionLen);
                        pointer += optionLen;
                        break;
                    case 13:
                        // nope
                        pointer++;
                        break;
                    case 14:
                        TSOffset = (long)PCAPNGBlock.GetUInt64(options, normalByteOrder, pointer);
                        pointer += 8;
                        break;
                    case 15: //TODO reverse order when needed
                        Hardware = Encoding.UTF8.GetString(options, pointer, optionLen);
                        pointer += optionLen;
                        break;
                    case 2988:
                    case 2989:
                    case 19372:
                    case 19373:
                        throw new NotImplementedException("Custom vendor options in PCAPNG not supported");
                }

                // pad to even quadruple
                while (pointer % 4 != 0)
                    pointer++;
            }
        }

        public UInt16 LinkLayerType { get; }
        public UInt32 SnapLen { get; }
        public string Name { get; }
        public string Description { get; }
        public IPAddress IPv4 { get; }
        public IPAddress IPv4SubNet { get; }
        public byte[] MAC { get; }
        public ulong BitsPerSecond { get; }

        /// <summary>
        /// This is complicated, please refer to PCAPNG spec
        /// </summary>
        public short TimeStampResolution { get; }

        public uint TimeZone { get; }
        public string OS { get; }
        public Int64 TSOffset { get; }
        public string Hardware { get; }
        public List<string> Comments { get; set; } = new List<string>();
    }
}
