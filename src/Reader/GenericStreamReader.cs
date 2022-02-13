using System;
using System.Collections.Generic;
using System.IO;

namespace BustPCap
{
    internal class GenericStreamReader
    {
        IReader _reader;
        int _buffersize;
        Stream _stream;

        public GenericStreamReader(IReader reader, int buffersize, Stream stream)
        {
            _reader = reader;
            _buffersize = buffersize;
            _stream = stream;
        }

        public IEnumerable<IBlock> Enumerate()
        {
            var buffer = new byte[_buffersize];

            while (_stream.CanRead)
            {
                var read = _stream.Read(buffer, 0, buffer.Length);
                if (read <= 0)
                    break;

                if (read == buffer.Length)
                {
                    if (_reader.Write(buffer) != null)
                        break;
                }
                else
                {
                    var cut = new byte[read];
                    Array.Copy(buffer, cut, read);
                    if (_reader.Write(cut) != null)
                        break;
                }

                while (_reader.ReadBlocks.Count > 0)
                    yield return _reader.ReadBlocks.Dequeue();
            }

            // pick up orphaned blocks in case stream terminated early
            while (_reader.ReadBlocks.Count > 0)
                yield return _reader.ReadBlocks.Dequeue();

            // blocks are already processed in the underlying stream, so let's just copy them over
            //this.StartTime = _reader.StartTime;
            //this.EndTime = _reader.EndTime;
            //this.Count = _reader.Count;
        }
    }
}