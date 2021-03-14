using System;
using System.Collections.Generic;
using System.IO;

namespace BustPCap
{
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
            var pcapReaderStream = new PCAPStream();

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
}
