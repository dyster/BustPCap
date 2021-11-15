using System;
using System.IO;
using System.IO.Compression;

namespace BustPCap
{
    public class PCAPWriter : IDisposable
    {
        private int _rotationIndex;
        private DateTime _startTime;
        private Stream _stream;

        /// <summary>
        /// Writes packets to a PCAP file, does not support timezone correction or orig_len currently
        /// </summary>
        /// <param name="folder">The folder where the file or files will be saved</param>
        /// <param name="filename">The filename, excluding extension</param>
        public PCAPWriter(string folder, string filenameTemplate)
        {
            FileNameTemplate = filenameTemplate;
            Folder = Directory.CreateDirectory(folder).FullName;
        }

        /// <summary>
        /// Writes packets to a PCAP file, does not support timezone correction or orig_len currently
        /// </summary>
        /// <param name="filePath">The file to write to (folder and filename will be used for rotation), extension excluded</param>
        public PCAPWriter(string filePath)
        {
            FileNameTemplate = Path.GetFileNameWithoutExtension(filePath);
            Folder = Directory.CreateDirectory(filePath.Substring(0, filePath.LastIndexOf('\\'))).FullName;
        }

        /// <summary>
        /// The link layer type, see http://www.tcpdump.org/linktypes.html
        /// </summary>
        public uint LinkLayerType { get; set; } = 1;

        /// <summary>
        /// The name of the file to write (extension excluded), used as base for rotation
        /// </summary>
        public string FileNameTemplate { get; }

        /// <summary>
        /// The folder where file(s) will be written
        /// </summary>
        public string Folder { get; }

        /// <summary>
        /// The number of seconds before file rotation occurs, 0 disables
        /// </summary>
        public int RotationTime { get; set; } = 0;

        /// <summary>
        /// The size in mb when the file will rotate, 0 disables
        /// </summary>
        public int RotationSize { get; set; } = 0;

        /// <summary>
        /// If true will gzip the files
        /// </summary>
        public bool Compress { get; set; } = false;

        private string Extension => Compress ? ".pcap.gz" : ".pcap";

        /// <summary>
        /// Forces writing all buffers to disk
        /// </summary>
        public void Flush()
        {
            _stream?.Flush();
        }

        /// <summary>
        /// Starts writing the file, and starts timer if time rotation is used
        /// </summary>
        public void Start()
        {
            _startTime = DateTime.Now; // DateTime.Now.ToString("yyyy-MM-dd HH.mm.ss")
            var currentFilename = "";
            var stamp = DateTime.Now.ToString("yyyy-MM-dd HH.mm.ss");

            if (RotationTime > 0 || RotationSize > 0)
            {
                currentFilename = Folder + "\\" + stamp + "_" + this.FileNameTemplate + "_" + _rotationIndex++ + Extension;
            }
            else
            {
                currentFilename = Folder + "\\" + stamp + "_" + this.FileNameTemplate + Extension;
            }

            while (File.Exists(currentFilename))
            {
                currentFilename = Folder + "\\" + stamp + "_" + this.FileNameTemplate + "_" + _rotationIndex++ + Extension;
            }

            _stream = File.Open(currentFilename, FileMode.Create, FileAccess.Write);

            if (Compress)
                _stream = new GZipStream(_stream, CompressionMode.Compress);

            WriteHeader();
        }

        /// <summary>
        /// Closes the current file
        /// </summary>
        public void Stop()
        {
            _stream?.Close();
        }

        private void WriteHeader()
        {
            //bytes[0] == 0xd4 && bytes[1] == 0xc3 && bytes[2] == 0xb2 && bytes[3] == 0xa1
            var magic = new byte[4] { 0xd4, 0xc3, 0xb2, 0xa1 };
            _stream.Write(magic, 0, magic.Length);

            ushort major = 2;
            ushort minor = 4;
            int thiszone = 0;
            uint sigfigs = 0;
            uint snaplen = uint.MaxValue;


            _stream.Write(BitConverter.GetBytes(major), 0, 2);
            _stream.Write(BitConverter.GetBytes(minor), 0, 2);
            _stream.Write(BitConverter.GetBytes(thiszone), 0, 4);
            _stream.Write(BitConverter.GetBytes(sigfigs), 0, 4);
            _stream.Write(BitConverter.GetBytes(snaplen), 0, 4);
            _stream.Write(BitConverter.GetBytes(LinkLayerType), 0, 4);
        }

        public void WritePacket(byte[] packet, DateTime timestamp)
        {
            uint seconds = Functions.DateTimeToUnixEpoch(timestamp);
            uint microseconds = Convert.ToUInt32(timestamp.ToString("ffffff"));
            WritePacket(packet, seconds, microseconds);
        }

        public void WritePacket(byte[] packet, uint ts_sec, uint ts_usec)
        {
            if (RotationSize > 0)
            {
                if (_stream is GZipStream)
                {
                    var gz = (GZipStream)_stream;
                    ;
                    if (gz.BaseStream.Position > RotationSize * 1024 * 1024)
                    {
                        Stop();
                        Start();
                    }
                }
                else
                {
                    if (_stream.Position > RotationSize * 1024 * 1024)
                    {
                        Stop();
                        Start();
                    }
                }

            }

            if (RotationTime > 0)
            {
                if (DateTime.Now.Subtract(_startTime).TotalSeconds > RotationTime)
                {
                    Stop();
                    Start();
                }
            }

            uint snap_len = (uint)packet.Length;
            uint orig_len = (uint)packet.Length; // lets not support this for now

            _stream.Write(BitConverter.GetBytes(ts_sec), 0, 4);
            _stream.Write(BitConverter.GetBytes(ts_usec), 0, 4);
            _stream.Write(BitConverter.GetBytes(snap_len), 0, 4);
            _stream.Write(BitConverter.GetBytes(orig_len), 0, 4);

            _stream.Write(packet, 0, packet.Length);
        }

        public void Dispose()
        {
            _stream?.Dispose();
        }
    }
}
