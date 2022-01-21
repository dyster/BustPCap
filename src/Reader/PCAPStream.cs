using System;
using System.Collections.Generic;
using System.IO;

namespace BustPCap
{
    /// <summary>
    /// As opposed to the StreamReader that reads an actual stream object, this is a read/write stream where you insert chunks of data and get PCAP blocks out.
    /// A PCAP pump
    /// </summary>
    public class PCAPStream : PCAPReader
    {
        private MemoryStream _stream = new MemoryStream();
        private bool _init = false;
        private long _position = 0;
        private long _writePosition = 0;

        public void Write(byte[] bytes)
        {
            Write(bytes, 0, bytes.Length);
        }

        /// <summary>
        /// Write raw data into the stream to be parsed as PCAP
        /// </summary>
        /// <param name="bytes"></param>
        public void Write(byte[] bytes, int offset, int length)
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
                    return;
                }

                var header = new byte[24];
                int read = _stream.Read(header, 0, header.Length);
                if (read != 24)
                    throw new Exception("Stream read problem");
                Header = new PCAPHeader(header);

                var isPCAP = header[0] == 0xd4 && header[1] == 0xc3 && header[2] == 0xb2 && header[3] == 0xa1 || header[0] == 0xa1 &&
                    header[1] == 0xb2 && header[2] == 0xc3 && header[3] == 0xd4;

                if (!isPCAP)
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
}
