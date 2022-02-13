using System.Collections.Generic;
using System.IO;

namespace BustPCap
{
    public class PCAPStreamReader : BaseReader
    {
        private readonly Stream _stream;

        public PCAPStreamReader(Stream stream)
        {
            _stream = stream;
        }

        public IEnumerable<PCAPBlock> Enumerate()
        {
            var pcapReaderStream = new PCAPStream();
            var genreader = new GenericStreamReader(pcapReaderStream, 4096, _stream);

            foreach (var block in genreader.Enumerate())
                yield return (PCAPBlock)block;

            // blocks are already processed in the underlying stream, so let's just copy them over
            this.StartTime = pcapReaderStream.StartTime;
            this.EndTime = pcapReaderStream.EndTime;
            this.Count = pcapReaderStream.Count;
        }
    }
}