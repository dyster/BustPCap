using System;
using Xunit;

namespace Tests
{
    public class FileTests
    {
        [Theory]
        [InlineData("TestFiles\\modern.pcap")]
        public void ModernWireshark(string path)
        {
            var ticksPerMicro = TimeSpan.TicksPerMillisecond / 1000;
            
            var start = DateTime.Parse("2021-03-14T16:10:14.9452330Z");
            var end = DateTime.Parse("2021-03-14T16:10:22.0056130Z");

            var file = new BustPCap.PCAPFileReader(path);
            foreach(var block in file.Enumerate())
            {

            }

            Assert.Equal(start, file.StartTime);
            Assert.Equal(end, file.EndTime);
        }
    }
}
