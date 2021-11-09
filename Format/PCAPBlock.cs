using System;

namespace BustPCap
{
    public class PCAPBlock : IBlock
    {
        private static DateTime _unixepoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified);
        public PCAPBlock(byte[] bytes, PCAPHeader header)
        {
            Header = header;
            var swapped = header.swapped;

            // yes, the reverse should only be called once. sue me

            // First 8 bytes is timestamp
            var ticks = new byte[4];
            Array.Copy(bytes, 0, ticks, 0, 4);
            if (swapped)
                Array.Reverse(ticks);

            DateTime dateTime = _unixepoch.AddSeconds(BitConverter.ToUInt32(ticks, 0));

            var msoffset = new byte[4];
            Array.Copy(bytes, 4, msoffset, 0, 4);
            if (swapped)
                Array.Reverse(msoffset);

            uint microseconds = BitConverter.ToUInt32(msoffset, 0);
            DateTime = dateTime.AddTicks((microseconds * TimeSpan.TicksPerMillisecond) / 1000);

            // then payload length
            var octets = new byte[4];
            Array.Copy(bytes, 8, octets, 0, octets.Length);
            if (swapped)
                Array.Reverse(octets);

            PayloadLength = BitConverter.ToUInt32(octets, 0);

            // and the original length
            var origlength = new byte[4];
            Array.Copy(bytes, 12, origlength, 0, origlength.Length);
            if (swapped)
                Array.Reverse(origlength);
            OriginalLength = BitConverter.ToUInt32(origlength, 0);
        }

        public DateTime DateTime { get; }
        public uint PayloadLength { get; }
        public uint OriginalLength { get; }
        public byte[] PayLoad { get; set; }
        public PCAPHeader Header { get; set; }
    }
}
