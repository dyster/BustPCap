using System;

namespace BustPCap
{
    public interface IBlock
    {
        DateTime DateTime { get; }
        byte[] PayLoad { get; set; }
        uint OriginalLength { get; }
        uint PayloadLength { get; }
    }
}