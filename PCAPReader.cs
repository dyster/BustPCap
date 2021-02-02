using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace BustPCap
{
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

    public class PCAPStreamReader : PCAPReader
    {
        private readonly Stream _stream;

        public PCAPStreamReader(Stream stream)
        {
            _stream = stream;
        }

        public IEnumerable<PCAPBlock> Enumerate()
        {
            var headerBytes = new byte[24];

            int read = _stream.Read(headerBytes, 0, headerBytes.Length);
            if (read != 24)
                throw new Exception("Stream read problem");
            var header = new PCAPHeader(headerBytes);
            
            while (_stream.Length - _stream.Position > 16)
            {
                var headerbytes = new byte[16];
                read = _stream.Read(headerbytes, 0, headerbytes.Length);
                if (read != headerbytes.Length)
                    throw new Exception("Stream read problem");

                if (headerbytes[0] == 0 && headerbytes[1] == 0 && headerbytes[2] == 0 && headerbytes[3] == 0)
                {
                    // File has ended prematurely probably, end? not sure what to do here
                    throw new NotImplementedException("This error is currently unhandled");
                }

                var pcapBlock = new PCAPBlock(headerbytes, header);
                

                pcapBlock.PayLoad = new byte[pcapBlock.PayloadLength];

                read = _stream.Read(pcapBlock.PayLoad, 0, pcapBlock.PayLoad.Length);
                if (read != pcapBlock.PayLoad.Length)
                    throw new Exception("Stream read problem");
                Process(pcapBlock);
                yield return pcapBlock;
            }
        }
    }

    public class PCAPFileReader : PCAPReader, IDisposable
    {
        private readonly FileStream _fileStream;

        public PCAPFileReader(FileStream fileStream)
        {
            _fileStream = fileStream;
        }

        public PCAPFileReader(string path)
        {
            _fileStream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        }

        public IEnumerable<PCAPBlock> Enumerate()
        {
            var buffer = new byte[61440];
            var pcapReaderStream = new PCAPReaderStream();

            long toRead = _fileStream.Length;
            while (toRead > 0)
            {
                var read = _fileStream.Read(buffer, 0, buffer.Length);
                if (read == 0)
                    break;

                if (read == buffer.Length)
                    pcapReaderStream.Write(buffer);
                else
                {
                    var cut = new byte[read];
                    Array.Copy(buffer, cut, read);
                    pcapReaderStream.Write(cut);
                }

                while (pcapReaderStream.ReadBlocks.Count > 0)
                    yield return pcapReaderStream.ReadBlocks.Dequeue();

                toRead -= read;

                // blocks are already processed in the underlying stream, so let's just copy them over
                this.StartTime = pcapReaderStream.StartTime;
                this.EndTime = pcapReaderStream.EndTime;
                this.Count = pcapReaderStream.Count;
            }
        }

        public void Dispose()
        {
            _fileStream?.Dispose();
        }
    }
    public class PCAPReaderStream : PCAPReader
    {
        private MemoryStream _stream = new MemoryStream();
        private bool _init = false;
        private long _position = 0;
        private long _writePosition = 0;

        /// <summary>
        /// Write raw data into the stream to be parsed as PCAP
        /// </summary>
        /// <param name="bytes"></param>
        public void Write(byte[] bytes)
        {
            // go to writing "mode"
            _stream.Position = _writePosition;
            _stream.Write(bytes, 0, bytes.Length);
            _writePosition = _stream.Position;

            // and then to reading "mode"
            _stream.Position = _position;
            

            if (!_init)
            {
                if (_stream.Length < 24)
                {
                    // not enough data to init, wait
                    return;
                }

                var header = new byte[24];
                int read = _stream.Read(header, 0, header.Length);
                if(read != 24)
                    throw new Exception("Stream read problem");
                Header = new PCAPHeader(header);

                var isPCAP = header[0] == 0xd4 && header[1] == 0xc3 && header[2] == 0xb2 && header[3] == 0xa1 || header[0] == 0xa1 &&
                    header[1] == 0xb2 && header[2] == 0xc3 && header[3] == 0xd4;

                if(!isPCAP)
                    throw new InvalidDataException("Stream was initialized with invalid data");

                _init = true;
            }

            while (_stream.Length - _stream.Position > 16)
            {
                var headerbytes = new byte[16];
                var read = _stream.Read(headerbytes, 0, headerbytes.Length);
                if (read != headerbytes.Length)
                    throw new Exception("Stream read problem");
                
                if (headerbytes[0] == 0 && headerbytes[1] == 0 && headerbytes[2] == 0 && headerbytes[3] == 0)
                {
                    // File has ended prematurely probably, end? not sure what to do here
                    throw new NotImplementedException("This error is currently unhandled");
                }

                var pcapBlock = new PCAPBlock(headerbytes, Header);


                if (_stream.Length - _stream.Position >= pcapBlock.PayloadLength)
                {
                    // LET'S ROCK

                    pcapBlock.PayLoad = new byte[pcapBlock.PayloadLength];

                    read = _stream.Read(pcapBlock.PayLoad, 0, pcapBlock.PayLoad.Length);
                    if (read != pcapBlock.PayLoad.Length)
                        throw new Exception("Stream read problem");
                    Process(pcapBlock);
                    ReadBlocks.Enqueue(pcapBlock);
                }
                else
                {
                    // LET'S NOT

                    _stream.Position -= 16;

                    // save for next time we read
                    _position = _stream.Position;
                    return;

                }

                

            }
            // save for next time we read
            _position = _stream.Position;

            if (_stream.Length > 5000)
            {
                var newstream = new MemoryStream();
                _stream.CopyTo(newstream);
                
                _stream = newstream;
                
                _writePosition = _stream.Position;
                _position = 0;
            }
        }

        public Queue<PCAPBlock> ReadBlocks { get; set; } = new Queue<PCAPBlock>();

        public PCAPHeader Header { get; set; }
    }

    public class PCAPBlock : IBlock
    {
        private static DateTime _unixepoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified);
        public PCAPBlock(byte[] bytes, PCAPHeader header)
        {
            Header = header;
            var swapped = header.swapped;

            // yes, the reverse should only be called once. sue me

            // First 8 bytes is timestamp
            var ticks = new byte[4];
            Array.Copy(bytes, 0, ticks, 0, 4);
            if (swapped)
                Array.Reverse(ticks);

            DateTime dateTime = _unixepoch.AddSeconds(BitConverter.ToUInt32(ticks, 0));

            var msoffset = new byte[4];
            Array.Copy(bytes, 4, msoffset, 0, 4);
            if (swapped)
                Array.Reverse(msoffset);

            uint microseconds = BitConverter.ToUInt32(msoffset, 0);
            DateTime = dateTime.AddTicks((microseconds * TimeSpan.TicksPerMillisecond) / 1000);

            // then payload length
            var octets = new byte[4];
            Array.Copy(bytes, 8, octets, 0, octets.Length);
            if (swapped)
                Array.Reverse(octets);

            PayloadLength = BitConverter.ToUInt32(octets, 0);

            // and the original length
            var origlength = new byte[4];
            Array.Copy(bytes, 12, origlength, 0, origlength.Length);
            if (swapped)
                Array.Reverse(origlength);
            OriginalLength = BitConverter.ToUInt32(origlength, 0);
        }

        public DateTime DateTime { get; }
        public uint PayloadLength { get; }
        public uint OriginalLength { get; }
        public byte[] PayLoad { get; set; }
        public PCAPHeader Header { get; set; }
    }

    public class PCAPHeader
    {
        public uint magic_number; /* magic number */
        public uint network; /* data link type */
        public uint sigfigs; /* accuracy of timestamps */
        public uint snaplen; /* max length of captured packets, in octets */
        public bool swapped; /* byte reading order */
        public int thiszone; /* GMT to local correction */
        public ushort version_major; /* major version number */
        public ushort version_minor; /* minor version number */

        public PCAPHeader(byte[] header)
        {
            magic_number = BitConverter.ToUInt32(header, 0);
            if (magic_number == 0xa1b2c3d4)
                swapped = false;
            else if (magic_number == 0xd4c3b2a1)
                swapped = true;


            if (swapped)
            {
                version_major = BitConverter.ToUInt16(new[] { header[5], header[4] }, 0);
                version_minor = BitConverter.ToUInt16(new[] { header[7], header[6] }, 0);
                thiszone = BitConverter.ToInt32(new[] { header[11], header[10], header[9], header[8] }, 0);
                sigfigs = BitConverter.ToUInt32(new[] { header[15], header[14], header[13], header[12] }, 0);
                snaplen = BitConverter.ToUInt32(new[] { header[19], header[18], header[17], header[16] }, 0);
                network = BitConverter.ToUInt32(new[] { header[23], header[22], header[21], header[20] }, 0);
            }
            else
            {
                version_major = BitConverter.ToUInt16(header, 4);
                version_minor = BitConverter.ToUInt16(header, 6);
                thiszone = BitConverter.ToInt32(header, 8);
                sigfigs = BitConverter.ToUInt32(header, 12);
                snaplen = BitConverter.ToUInt32(header, 16);
                network = BitConverter.ToUInt32(header, 20);
            }
        }

        public override string ToString()
        {
            // haters gonna hate
            return string.Join("|", this.GetType().GetProperties().Select(prop => prop.Name +": "+prop.GetValue(this, null)));
        }
    }
}
