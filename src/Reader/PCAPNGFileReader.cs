using System;
using System.Collections.Generic;
using System.IO;

namespace BustPCap
{
    public class PCAPNGFileReader : PCAPReader, IDisposable
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
            var buffer = new byte[61440];
            var pcapReaderStream = new PCAPNGStream();

            long toRead = _fileStream.Length;
            while (toRead > 0)
            {
                var read = _fileStream.Read(buffer, 0, buffer.Length);
                if (read == 0)
                    break;

                if (read == buffer.Length)
                {
                    if (pcapReaderStream.Write(buffer) != null)
                        break;
                }
                else
                {
                    var cut = new byte[read];
                    Array.Copy(buffer, cut, read);
                    if (pcapReaderStream.Write(cut) != null)
                        break;
                }

                while (pcapReaderStream.ReadBlocks.Count > 0)
                    yield return pcapReaderStream.ReadBlocks.Dequeue();

                toRead -= read;

                
            }

            // pick up orphaned blocks in case stream terminated early
            while (pcapReaderStream.ReadBlocks.Count > 0)
                yield return pcapReaderStream.ReadBlocks.Dequeue();

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
