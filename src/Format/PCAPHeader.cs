using System;
using System.Linq;

namespace BustPCap
{
    public class PCAPHeader
    {
        public uint magic_number; /* magic number */
        public uint network; /* data link type */
        public uint sigfigs; /* accuracy of timestamps */
        public uint snaplen; /* max length of captured packets, in octets */
        public bool swapped; /* byte reading order */
        public int thiszone; /* GMT to local correction */
        public ushort version_major; /* major version number */
        public ushort version_minor; /* minor version number */

        public PCAPHeader(byte[] header)
        {
            // https://wiki.wireshark.org/Development/LibpcapFileFormat
            // since the ordering can be confusing, the term swapped here is the one from the wireshark wiki
            // so swapped means the first byte in the file is D4

            // this actually swaps the order
            magic_number = BitConverter.ToUInt32(header, 0);

            if (magic_number == 0xa1b2c3d4)
                swapped = true;
            else if (magic_number == 0xd4c3b2a1)
                swapped = false;


            if (swapped)
            {
                version_major = BitConverter.ToUInt16(header, 4);
                version_minor = BitConverter.ToUInt16(header, 6);
                thiszone = BitConverter.ToInt32(header, 8);
                sigfigs = BitConverter.ToUInt32(header, 12);
                snaplen = BitConverter.ToUInt32(header, 16);
                network = BitConverter.ToUInt32(header, 20);
            }
            else
            {
                version_major = BitConverter.ToUInt16(new[] { header[5], header[4] }, 0);
                version_minor = BitConverter.ToUInt16(new[] { header[7], header[6] }, 0);
                thiszone = BitConverter.ToInt32(new[] { header[11], header[10], header[9], header[8] }, 0);
                sigfigs = BitConverter.ToUInt32(new[] { header[15], header[14], header[13], header[12] }, 0);
                snaplen = BitConverter.ToUInt32(new[] { header[19], header[18], header[17], header[16] }, 0);
                network = BitConverter.ToUInt32(new[] { header[23], header[22], header[21], header[20] }, 0);
            }
        }

        public override string ToString()
        {
            // haters gonna hate
            return string.Join("|", this.GetType().GetProperties().Select(prop => prop.Name + ": " + prop.GetValue(this, null)));
        }
    }
}
