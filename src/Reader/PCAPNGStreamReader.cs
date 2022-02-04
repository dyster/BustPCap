using System;
using System.Collections.Generic;
using System.IO;

namespace BustPCap
{
    public class PCAPNGStreamReader : PCAPReader
    {
        private readonly Stream _stream;

        public PCAPNGStreamReader(Stream stream)
        {
            _stream = stream;
        }

        public IEnumerable<PCAPNGBlock> Enumerate()
        {
            var stream = _stream;

            long streamlength = stream.Length;

            var list = new List<PCAPNGBlock>();
            var linklayertypes = new List<InterfaceDescription>();
            bool normalByteOrder = false;
            uint length;

            var oldprogress = 0;

            for (long i = 0; i < streamlength;)
            {
                var headerbytes = new byte[4];
                i += stream.Read(headerbytes, 0, headerbytes.Length);
                var isSectionHeader = IsPCAPNG(headerbytes);


                var lengthbytes = new byte[4];
                if (isSectionHeader)
                {
                    linklayertypes.Clear();

                    i += stream.Read(lengthbytes, 0, lengthbytes.Length);

                    var magicbytes = new byte[4];
                    i += stream.Read(magicbytes, 0, magicbytes.Length);



                    // the author will consider reversed order as "normal" because then it matches the C# order 

                    if (magicbytes[0] == 0x1A && magicbytes[1] == 0x2B && magicbytes[2] == 0x3c && magicbytes[3] == 0x4d)
                    {
                        // normal magic bytes
                        normalByteOrder = false;

                        // taking the plunge of implementing it now
                        //throw new NotImplementedException(
                        //    "The byte order of the PCAPNG file has not been implemented");
                    }
                    else if (magicbytes[0] == 0x4d && magicbytes[1] == 0x3c && magicbytes[2] == 0x2b && magicbytes[3] == 0x1a)
                    {
                        // reversed order magic bytes
                        normalByteOrder = true;
                    }
                    else
                    {
                        throw new InvalidDataException("Incorrect PCAPNG magic bytes!");
                    }
                }
                else
                {
                    i += stream.Read(lengthbytes, 0, lengthbytes.Length);
                }

                length = PCAPNGBlock.GetUInt32(lengthbytes, normalByteOrder, 0);

                var currentblock = new PCAPNGBlock(headerbytes, normalByteOrder);
                list.Add(currentblock);


                byte[] data;
                if (currentblock.Header == PCAPNGHeader.SectionHeader)
                {
                    // extra deduction for the magic bytes
                    data = new byte[length - 16];
                }
                else
                {
                    data = new byte[length - 12];
                }

                i += stream.Read(data, 0, data.Length);




                switch (currentblock.Header)
                {
                    case PCAPNGHeader.EnhancedPacket:
                        uint interfaceId = PCAPNGBlock.GetUInt32(data, normalByteOrder, 0);
                        var currentInterface = linklayertypes[(int)interfaceId];
                        currentblock.LinkLayerType = currentInterface.LinkLayerType;

                        uint highstamp = PCAPNGBlock.GetUInt32(data, normalByteOrder, 4);
                        uint lowstamp = PCAPNGBlock.GetUInt32(data, normalByteOrder, 8);




                        //ulong ticks = BitConverter.ToUInt64(data, 4);

                        //var revstamp = new byte[] { data[11], data[10], data[9], data[8], data[7], data[6], data[5], data[4] };
                        //ulong superstamp = BitConverter.ToUInt64(data, 4);
                        //ulong revver = BitConverter.ToUInt64(revstamp, 0);
                        //ulong ticks = (ulong) (lowstamp * 4294967296 + highstamp);

                        var unixepoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified);

                        if (currentInterface.TimeStampResolution == 0)
                        {
                            // if the resolution is not set, assume power of 6 which is standard pcap

                            // a C# tick is a hundred nanoseconds, which is 10 times the standard pcap tick
                            // do a span per half to make sure we don't get signed byte problems
                            TimeSpan span1 = TimeSpan.FromTicks(lowstamp * 10);
                            TimeSpan span2 = TimeSpan.FromTicks(highstamp * 4294967296 * 10);
                            currentblock.DateTime = unixepoch + span1 + span2;
                        }
                        else if (currentInterface.TimeStampResolution > 0)
                        {
                            var negpower = currentInterface.TimeStampResolution;

                            // could compare power level and do this maybe for higher precision
                            // power of 1, * 1000000
                            // power of 3, * 10000
                            // power of 9, / 100

                            // but lets do second conversion and see how it goes
                            // compared the calculation below to a direct integer multiplication at nanosecond precision specified, and there was no loss of precision, so sticking with it

                            double pow = Math.Pow(10, -negpower);
                            double low = lowstamp * pow;
                            double high = (highstamp * 4294967296) * pow;

                            var ticks = (low + high) * Math.Pow(10, 7);
                            currentblock.DateTime = unixepoch + TimeSpan.FromTicks((long)ticks);
                        }


                        uint capturedLength = PCAPNGBlock.GetUInt32(data, normalByteOrder, 12);
                        currentblock.OriginalLength = PCAPNGBlock.GetUInt32(data, normalByteOrder, 16);
                        currentblock.PayLoad = new byte[capturedLength];
                        Buffer.BlockCopy(data, 20, currentblock.PayLoad, 0, (int)capturedLength);

                        long optionslength = data.Length - (capturedLength + 20);

                        if (optionslength > 3)
                        {
                            //throw new NotImplementedException();
                        }

                        break;

                    case PCAPNGHeader.InterfaceDescription:
                        var interfaceDescription = new InterfaceDescription(data, normalByteOrder);

                        linklayertypes.Add(interfaceDescription);
                        break;
                    case PCAPNGHeader.SectionHeader:
                        // this is handled in block start now instead                                    

                        break;
                    default:
                        break;
                }


                if (currentblock.PayLoad != null)
                {
                    yield return currentblock;
                }





                var endbytes = new byte[4];
                i += stream.Read(endbytes, 0, endbytes.Length);
                uint endlength = PCAPNGBlock.GetUInt32(endbytes, normalByteOrder, 0);

                Process(currentblock);

                if (endlength != length)
                    throw new InvalidDataException();
                
            }
        }
    }
}
