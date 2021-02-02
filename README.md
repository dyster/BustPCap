# BustPCap
A native C# PCAP read/write library

Am aware that there are other libraries available, but they did not fulfill all my needs, and not all are native managed C#.
The main functionality this library offers compared to others is to stream PCAP data remotely, enabling saving packets from tcpdump over SSH, without just dumping the stream straight to disk (and reading the packets on the fly)

Supports Net Standard 2.0, .NET 5 and .NET 4 Client Profile (to work on XP)
