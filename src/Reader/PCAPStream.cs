using System.Collections.Generic;
using System.IO;

namespace BustPCap
{
    /// <summary>
    /// As opposed to the StreamReader that reads an actual stream object, this is a read/write stream where you insert chunks of data and get PCAP blocks out.
    /// A PCAP pump
    /// </summary>
    public class PCAPStream : BaseReader, IReader
    {
        private MemoryStream _stream = new MemoryStream();
        private bool _init = false;
        private long _position = 0;
        private long _writePosition = 0;

        public string Write(byte[] bytes)
        {
            return Write(bytes, 0, bytes.Length);
        }

        /// <summary>
        /// Write raw data into the stream to be parsed as PCAP
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns>null if terminated correctly, or string on error</returns>
        public string Write(byte[] bytes, int offset, int length)
        {
            // go to writing "mode"
            _stream.Position = _writePosition;
            _stream.Write(bytes, offset, length);
            _writePosition = _stream.Position;

            // and then to reading "mode"
            _stream.Position = _position;


            if (!_init)
            {
                if (_stream.Length < 24)
                {
                    // not enough data to init, wait
                    return null;
                }

                var header = new byte[24];
                int read = _stream.Read(header, 0, header.Length);
                if (read != header.Length)
                    return "Stream read problem";
                Header = new PCAPHeader(header);

                var isPCAP = IsPCAP(header);

                if (!isPCAP)
                    return "Stream was initialized with invalid data";

                _init = true;
            }

            while (_stream.Length - _stream.Position >= 16)
            {
                var headerbytes = new byte[16];
                var read = _stream.Read(headerbytes, 0, headerbytes.Length);
                if (read != headerbytes.Length)
                    return "Stream read problem";

                if (headerbytes[0] == 0 && headerbytes[1] == 0 && headerbytes[2] == 0 && headerbytes[3] == 0)
                {
                    // File has ended prematurely probably, end? not sure what to do here
                    return "empty header, file ended prematurely";
                }

                var pcapBlock = new PCAPBlock(headerbytes, Header);


                if (_stream.Length - _stream.Position >= pcapBlock.PayloadLength)
                {
                    // LET'S ROCK

                    pcapBlock.PayLoad = new byte[pcapBlock.PayloadLength];

                    read = _stream.Read(pcapBlock.PayLoad, 0, pcapBlock.PayLoad.Length);
                    if (read != pcapBlock.PayLoad.Length)
                        return "Stream read problem";
                    Process(pcapBlock);
                    ReadBlocks.Enqueue(pcapBlock);
                }
                else
                {
                    // LET'S NOT

                    _stream.Position -= 16;

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

        public PCAPHeader Header { get; set; }
    }
}