using System;

namespace BustPCap
{
    public interface IBlock
    {
        DateTime DateTime { get; set; }
        byte[] PayLoad { get; set; }
        uint OriginalLength { get; }
        int PayloadLength { get; }
    }
}