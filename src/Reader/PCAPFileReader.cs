using System;
using System.Collections.Generic;
using System.IO;

namespace BustPCap
{
    public class PCAPFileReader : BaseReader, IDisposable
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
            var pcapReaderStream = new PCAPStream();

            var genreader = new GenericStreamReader(pcapReaderStream, 61440, _fileStream);

            foreach (var block in genreader.Enumerate())
                yield return (PCAPBlock)block;

            // blocks are already processed in the underlying stream, so let's just copy them over
            this.StartTime = pcapReaderStream.StartTime;
            this.EndTime = pcapReaderStream.EndTime;
            this.Count = pcapReaderStream.Count;
        }

        public void Dispose()
        {
            _fileStream?.Dispose();
        }
    }
}
