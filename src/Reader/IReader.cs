using System;
using System.Collections.Generic;

namespace BustPCap
{
    internal interface IReader
    {
        Queue<IBlock> ReadBlocks { get; }
        DateTime StartTime { get; }
        DateTime EndTime { get; }
        int Count { get; }

        string Write(byte[] buffer);
    }
}