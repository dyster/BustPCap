using System;
using System.Collections.Generic;
using System.IO;

namespace BustPCap
{
    public class PCAPNGStream : BaseReader, IReader
    {
        private MemoryStream _stream = new MemoryStream();
        private bool _init = false;
        private long _position = 0;
        private long _writePosition = 0;
        bool normalByteOrder = false;
        List<InterfaceDescription> linklayertypes = new List<InterfaceDescription>();

        public string Write(byte[] bytes)
        {
            return Write(bytes, 0, bytes.Length);
        }

        public string Write(byte[] bytes, int offset, int inputlength)
        {
            // go to writing "mode"
            _stream.Position = _writePosition;
            _stream.Write(bytes, offset, inputlength);
            _writePosition = _stream.Position;

            // and then to reading "mode"
            _stream.Position = _position;

            if (!_init)
            {
                if (_stream.Length <= 28)
                {
                    // not enough data to init, wait
                    return null;
                }

                var header = new byte[4];
                int read = _stream.Read(header, 0, header.Length);
                if (read != header.Length)
                {
                    Log($"Stream read problem, asked for {header.Length} bytes, got {read}");
                    return $"Stream read problem, asked for {header.Length} bytes, got {read}"; 
                }

                if (!IsPCAPNG(header))
                {
                    Log("Stream was initialized with invalid data");
                    return "Stream was initialized with invalid data";
                }

                _stream.Position = 0;
                _init = true;
            }


            while (_stream.Length - _stream.Position >= 12)
            {
                var headerbytes = new byte[4];
                var read = _stream.Read(headerbytes, 0, headerbytes.Length);


                if (headerbytes[0] == 0 && headerbytes[1] == 0 && headerbytes[2] == 0 && headerbytes[3] == 0)
                {
                    // File has ended prematurely probably, end? not sure what to do here
                    Log("empty header, file ended prematurely");
                    return "empty header, file ended prematurely";
                }

                var lengthbytes = new byte[4];

                if (IsPCAPNG(headerbytes)) // this means we are on a section header
                {
                    linklayertypes.Clear();

                    read += _stream.Read(lengthbytes, 0, lengthbytes.Length);


                    var magicbytes = new byte[4];
                    read += _stream.Read(magicbytes, 0, magicbytes.Length);


                    // the author will consider reversed order as "normal" because then it matches the C# order 
                    if (magicbytes[0] == 0x1A && magicbytes[1] == 0x2B && magicbytes[2] == 0x3c &&
                        magicbytes[3] == 0x4d)
                    {
                        // normal magic bytes
                        normalByteOrder = false;
                    }
                    else if (magicbytes[0] == 0x4d && magicbytes[1] == 0x3c && magicbytes[2] == 0x2b &&
                             magicbytes[3] == 0x1a)
                    {
                        // reversed order magic bytes
                        normalByteOrder = true;
                    }
                    else
                    {
                        Log("Incorrect PCAPNG magic bytes");
                        return "Incorrect PCAPNG magic bytes";
                    }
                }
                else
                {
                    read += _stream.Read(lengthbytes, 0, lengthbytes.Length);
                }

                uint length = PCAPNGBlock.GetUInt32(lengthbytes, normalByteOrder, 0);

                var currentblock = new PCAPNGBlock(headerbytes, normalByteOrder);

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

                if (_stream.Length - _stream.Position >=
                    data.Length + 4) // the remaining stream needs to contain payload + the endlength bytes
                {
                    // LET'S ROCK

                    read = _stream.Read(data, 0, data.Length);
                    if (read != data.Length)
                    {
                        Log($"Stream read problem, asked for {data.Length} bytes, got {read}");
                        return $"Stream read problem, asked for {data.Length} bytes, got {read}";
                    }


                    switch (currentblock.Header)
                    {
                        case PCAPNGHeader.EnhancedPacket:
                            uint interfaceId = PCAPNGBlock.GetUInt32(data, normalByteOrder, 0);
                            var currentInterface = linklayertypes[(int)interfaceId];
                            currentblock.LinkLayerType = currentInterface.LinkLayerType;

                            uint highstamp = PCAPNGBlock.GetUInt32(data, normalByteOrder, 4);
                            uint lowstamp = PCAPNGBlock.GetUInt32(data, normalByteOrder, 8);
                            ulong stamp = PCAPNGBlock.GetUInt64(data, normalByteOrder, 4);
                            var mod = Math.Pow(10, -6);
                            var seconds = stamp * mod;

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
                                TimeSpan span = TimeSpan.FromSeconds(seconds);
                                var datetime = unixepoch + span;
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
                            Log(interfaceDescription.ToString());
                            linklayertypes.Add(interfaceDescription);
                            break;
                        case PCAPNGHeader.SectionHeader:
                            // this is handled in block start now instead                                    

                            break;
                        default:
                            break;
                    }

                    var endbytes = new byte[4];
                    read = _stream.Read(endbytes, 0, endbytes.Length);
                    uint endlength = PCAPNGBlock.GetUInt32(endbytes, normalByteOrder, 0);

                    Process(currentblock);
                    ReadBlocks.Enqueue(currentblock);

                    if (endlength != length)
                    {
                        Log($"End length mismatch, endlength: {endlength} length {length}");
                        return $"End length mismatch, endlength: {endlength} length {length}";
                    }
                }
                else
                {
                    // LET'S NOT

                    // back up so we can start again
                    _stream.Position -= read;

                    // save for next time we read
                    _position = _stream.Position;
                    return null;
                }
            }

            // save for next time we read
            _position = _stream.Position;

            // slice off already processed data
            if (_stream.Length > 5000)
            {
                var newstream = new MemoryStream();
                _stream.CopyTo(newstream);

                _stream = newstream;

                _writePosition = _stream.Position;
                _position = 0;
            }

            return null;
        }

        public Queue<IBlock> ReadBlocks { get; set; } = new Queue<IBlock>();

        //public PCAPNGHeader Header { get; set; }
    }
}