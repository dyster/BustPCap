using System;
using System.Collections.Generic;
using System.IO;

namespace BustPCap
{
    public class PCAPNGFileReader : BaseReader, IDisposable
    {
        private readonly FileStream _fileStream;

        public PCAPNGFileReader(FileStream fileStream)
        {
            _fileStream = fileStream;
        }

        public PCAPNGFileReader(string path)
        {
            _fileStream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        }

        public IEnumerable<PCAPNGBlock> Enumerate()
        {
            var pcapReaderStream = new PCAPNGStream();
            var genreader = new GenericStreamReader(pcapReaderStream, 61440, _fileStream);

            foreach(var block in genreader.Enumerate())
                yield return (PCAPNGBlock)block;
            
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
