# Custom tcpdump
mydump is a passive network monitoring application written in C using the libpcap packet capture library. mydump captures the traffic from a network interface in promiscuous mode (or reads the packets from a pcap trace file) and print a record for each packet in its standard output, much like a simplified version of tcpdump. The user can specify a BPF filter for capturing a subset of the traffic, and/or a string pattern for capturing only packets with matching payloads.

Command Line Format:

mydump [-i interface] [-r file] [-s string] expression

-i  Listen on network device <interface> (e.g., eth0). If not specified, mydump selects a default interface to listen on.

-r  Reads packets from <file> (tcpdump format)

-s  Keep only packets that contain <string> in their payload.

<expression> is a BPF filter that specifies which packets should be dumped. If no
filter is given, all packets seen on the interface (or contained in the trace)
are dumped. Otherwise, only packets matching <expression> are be dumped.

For each packet, mydump outputs a record containing the timestamp, source and
destination MAC address, EtherType, packet length, source and destination IP
address and port, protocol (TCP, UDP, ICMP, OTHER), and the raw content of the
application-layer packet payload.

