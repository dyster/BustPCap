# BustPCap
A native C# PCAP read/write library

Am aware that there are other libraries available, but they did not fulfill all my needs, and not all are native managed C#.
The main functionality this library offers compared to others is to stream PCAP data remotely, enabling saving packets from tcpdump over SSH, without just dumping the stream straight to disk (and reading the packets on the fly)

Supports Net Standard 2.0, .NET 5 and .NET 4 Client Profile (to work on XP)

An example to stream tcpdump remotely, I use Renci SSH and connect a normal client and run the command
`mkfifo /tmp/remcap`
then, I create this command and run it async with Begin.Execute and capture the stream output
`cat /tmp/remcap`
then create and run another command async
`tcpdump -s 0 -U -n -w - -i any 'not port 22' > /tmp/remcap`
    
Data then starts appearing in the stream connected to the "cat" command, which can be pumped into the PCAPStream class Write method and PCAP blocks come out the other end.
There are other ways but this works great for me on most linux distros.
