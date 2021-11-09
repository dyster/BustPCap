using Xunit;
using BustPCap;
using System;
using System.Collections.Generic;
using System.Text;

namespace BustPCap.Tests
{
    public class PCAPHeaderTests
    {
        [Fact]
        public void PCAPHeaderTestNormalByteOrder()
        {
            var headerBytes = new List<byte>();
            headerBytes.AddRange(new byte[4] { 0xA1, 0xB2, 0xC3, 0xD4 }); // standard magic bytes
            headerBytes.AddRange(new byte[2] { 0x00, 0x02}); // major version
            headerBytes.AddRange(new byte[2] { 0x00, 0x04 }); // minor version
            headerBytes.AddRange(new byte[4] { 0x00, 0x00, 0x00, 0x00 }); // timezone correction
            headerBytes.AddRange(new byte[4] { 0x00, 0x00, 0x00, 0x00 }); // sigfigs
            headerBytes.AddRange(new byte[4] { 0xFF, 0xFF, 0xFF, 0xFF }); // snaplen
            headerBytes.AddRange(new byte[4] { 0x00, 0x00, 0x00, 0x01 }); // network type, 1 for ethernet

            var header = new PCAPHeader(headerBytes.ToArray());

            Assert.False(header.swapped);
            Assert.Equal(BitConverter.ToUInt32(new byte[] { 0xA1, 0xB2, 0xC3, 0xD4 }), header.magic_number);
            Assert.Equal(2, header.version_major);
            Assert.Equal(4, header.version_minor);
            Assert.Equal(0, header.thiszone);
            Assert.Equal((uint)0, header.sigfigs);
            Assert.Equal(uint.MaxValue, header.snaplen);
            Assert.Equal((uint)1, header.network);
                        
        }

        [Fact]
        public void PCAPHeaderTestReverseByteOrder()
        {
            var headerBytes = new List<byte>();
            headerBytes.AddRange(new byte[4] { 0xD4, 0xC3, 0xB2, 0xA1 }); // standard magic bytes
            headerBytes.AddRange(new byte[2] { 0x02, 0x00 }); // major version
            headerBytes.AddRange(new byte[2] { 0x04, 0x00 }); // minor version
            headerBytes.AddRange(new byte[4] { 0x00, 0x00, 0x00, 0x00 }); // timezone correction
            headerBytes.AddRange(new byte[4] { 0x00, 0x00, 0x00, 0x00 }); // sigfigs
            headerBytes.AddRange(new byte[4] { 0xFF, 0xFF, 0xFF, 0xFF }); // snaplen
            headerBytes.AddRange(new byte[4] { 0x01, 0x00, 0x00, 0x00 }); // network type, 1 for ethernet

            var header = new PCAPHeader(headerBytes.ToArray());

            Assert.True(header.swapped);
            Assert.Equal(BitConverter.ToUInt32(new byte[] { 0xD4, 0xC3, 0xB2, 0xA1 }), header.magic_number);
            Assert.Equal(2, header.version_major);
            Assert.Equal(4, header.version_minor);
            Assert.Equal(0, header.thiszone);
            Assert.Equal((uint)0, header.sigfigs);
            Assert.Equal(uint.MaxValue, header.snaplen);
            Assert.Equal((uint)1, header.network);

        }
    }
}