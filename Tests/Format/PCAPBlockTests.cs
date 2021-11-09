using Xunit;
using BustPCap;
using System;
using System.Collections.Generic;
using System.Text;

namespace BustPCap.Tests
{
    public class PCAPBlockTests
    {
        [Fact()]
        public void PCAPBlockTest()
        {
            var headerBytes = new List<byte>();
            headerBytes.AddRange(new byte[4] { 0xA1, 0xB2, 0xC3, 0xD4 }); // standard magic bytes
            headerBytes.AddRange(new byte[2] { 0x00, 0x02 }); // major version
            headerBytes.AddRange(new byte[2] { 0x00, 0x04 }); // minor version
            headerBytes.AddRange(new byte[4] { 0x00, 0x00, 0x00, 0x00 }); // timezone correction
            headerBytes.AddRange(new byte[4] { 0x00, 0x00, 0x00, 0x00 }); // sigfigs
            headerBytes.AddRange(new byte[4] { 0xFF, 0xFF, 0xFF, 0xFF }); // snaplen
            headerBytes.AddRange(new byte[4] { 0x00, 0x00, 0x00, 0x01 }); // network type, 1 for ethernet

            var header = new PCAPHeader(headerBytes.ToArray());

            var blockBytes = new List<byte>();
            blockBytes.AddRange(new byte[4] { 0x19, 0xCF, 0xE4, 0x50 }); // unix timestamp
            blockBytes.AddRange(new byte[4] { 0x00, 0x01, 0xE2, 0x40 }); // microsecond offset
            blockBytes.AddRange(new byte[4] { 0x00, 0x00, 0x00, 0x04 }); // data length
            blockBytes.AddRange(new byte[4] { 0x00, 0x00, 0x00, 0x06 }); // original length

            blockBytes.AddRange(new byte[4] { 0x01, 0x02, 0x03, 0x04 }); // data

            var block = new PCAPBlock(blockBytes.ToArray(), header);
            var ticksPerMicro = TimeSpan.TicksPerMillisecond / 1000;
            var datetime = new DateTime(1983, 9, 22, 5, 0, 0, DateTimeKind.Utc).AddTicks(123456*ticksPerMicro);
            
            Assert.Equal(datetime, block.DateTime);
            Assert.Equal((uint)4, block.PayloadLength);
            Assert.Equal((uint)6, block.OriginalLength);
            
            // the payload is not assigned in the constructor to allow streaming implementations
            //Assert.Equal((uint)block.PayLoad.Length, block.PayloadLength);
            //Assert.Equal(new byte[4] { 0x01, 0x02, 0x03, 0x04 }, block.PayLoad);
            
        }
    }
}