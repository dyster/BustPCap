using System;
using System.Collections.Generic;
using System.IO;

namespace BustPCap
{
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
}
