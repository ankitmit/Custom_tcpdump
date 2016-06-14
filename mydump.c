#include <stdio.h>
#include <pcap.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>   //Declarations for icmp header
#include <netinet/udp.h>   //Declarations for udp header
#include <netinet/tcp.h>   //Declarations for tcp header
#include <netinet/if_ether.h>  //For ETH_P_ALL
#include <net/ethernet.h>  //For ethernet_header
#include <limits.h>
#include <unistd.h>
#include <ctype.h>
#include <arpa/inet.h>

#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
#define SIZE_ETHERNET 14

typedef struct
{
	char* file_name;
	char* interface;
	char* matching_string;
	char* filter_exp;
	int offline_scanning;
}command_line_args;

//function prototype declarations
void print_hex_ascii_line(const u_char *payload, int len, int offset);
void print_payload(const u_char *payload, int len);
char* bin_to_strdecimal(const u_char *bin, unsigned int binsz);
int sniffLiveConnection(command_line_args* args);
int parsePcapFile(command_line_args* args);
void parsePacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
const char *timestamp_string(struct timeval ts);
char* bin_to_strhex(const u_char *bin, unsigned int binsz, char delim);

struct sniff_arphdr 
{ 
    u_int16_t htype;    /* Hardware Type           */ 
    u_int16_t ptype;    /* Protocol Type           */ 
    u_char hlen;        /* Hardware Address Length */ 
    u_char plen;        /* Protocol Address Length */ 
    u_int16_t oper;     /* Operation Code          */ 
    u_char sha[6];      /* Sender hardware address */ 
    u_char spa[4];      /* Sender IP address       */ 
    u_char tha[6];      /* Target hardware address */ 
    u_char tpa[4];      /* Target IP address       */ 
};

struct out_format
{
	const char *ts;
	const char *src_MAC;
	const char *dest_MAC;
	char* h_proto;
	u_int packet_len;
	char *src_IP_ARP;
	char *dst_IP_ARP;
	char src_IP[INET6_ADDRSTRLEN];
	char dst_IP[INET6_ADDRSTRLEN];
	u_short sport, dport;
	char* ip_proto;
	const char* pay_load;
	u_short pay_load_length;
};


const struct ethhdr *ethernet; /* The ethernet header */
const struct iphdr *ip; /* The IP header */
const char *payload; /* Packet payload */

u_int size_ip;
u_int size_tcp;

void displayHelpText()
{
	printf("mydump [-i interface] [-r file] [-s string] expression\n");
	exit(0);
}
command_line_args* parse_command_line(int argc, char *argv[])
{
	int opt;
	command_line_args* args = (command_line_args*)malloc(sizeof(command_line_args));
	args->offline_scanning = 1;
	while ((opt = getopt(argc, argv, "i:r:s:")) != -1) 
	{
		switch(opt) 
		{
			case 'i':
				args->interface = optarg;
				args->offline_scanning = 0;
				break;
			case 'r':
				args->file_name = optarg;
				break;
			case 's':
				args->matching_string = optarg;
				break;
			case '?':
				// when user didn't specify argument
				if (optopt == 'i') 
				{
					printf("Interface must be specified. Please refer to the help text below\n");
					displayHelpText();
				}
				else if (optopt == 'r') 
				{
					printf("Pcap file to be parsed must be specified. Please refer to the help text below\n");
					displayHelpText();
				} 
				else 
				{
					printf("Unknown argument.Please refer to the help text below\n");
					displayHelpText();
				}
			default:
				printf("Default case?!\n");
				exit(1);
		}
	}
	if (optind == argc - 1) 
	{
		args->filter_exp = argv[optind];
	}
	return args;
}
int main(int argc, char *argv[])
{
	//get the command line arguments
	command_line_args* args = parse_command_line(argc, argv);
	if(args->offline_scanning)
	{
		parsePcapFile(args);
	}
	else
	{
		sniffLiveConnection(args);
	}
	return(0);
}
int parsePcapFile(command_line_args* args)
{
	const unsigned char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	bpf_u_int32 net = 0;
	
	struct bpf_program fp;
	
	pcap_t *handle = pcap_open_offline(args->file_name, errbuf);
	
	if (handle == NULL)
	{
		fprintf(stderr, "Unable to open file: %s\n", errbuf);
		exit(1);
	}
	
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, args->filter_exp, 0, net) == -1) 
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n", args->filter_exp, pcap_geterr(handle));
		return(2);
	}
	
	if (pcap_setfilter(handle, &fp) == -1) 
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", args->filter_exp, pcap_geterr(handle));
		return(2);
	}
	
	pcap_loop(handle, -1, parsePacket, (u_char*) args);
	//pcap_loop(handle,0,parsePacket,matching_string);

	return 0;
}
void printOutputPacket(struct out_format *output)
{
	if(!output)
	{
		return;
	}

	char *outstr = (char*)malloc(sizeof(char) * INT_MAX);
	int length = 0;
	length += sprintf(outstr + length, "%s %s -> %s, ethertype %s, length %d: ", output->ts, output->src_MAC,output->dest_MAC,output->h_proto,output->packet_len);
	
	if(output->h_proto == "ARP")
	{
		length += sprintf(outstr + length, "Request who-has %s tell %s",output->dst_IP_ARP,output->src_IP_ARP);
	}
	else
	{
		length += sprintf(outstr + length, "%s.%d -> %s.%d: %s", output->src_IP, output->sport, output->dst_IP, output->dport,output->ip_proto);	
	}
	printf("%s\n", outstr);
	if(output->h_proto == "IPv4" && output->pay_load_length > 0)
	{
		print_payload(output->pay_load, output->pay_load_length);
	}
}
void parsePacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	bool printPacket = false;
	struct timeval ts = header->ts;
	unsigned int capture_len = header->caplen;
	struct out_format* output = (struct out_format *) malloc(sizeof(struct out_format));
	command_line_args* args_orig = (command_line_args*) args;
	if(!output)
		return;
	
	output->ts = timestamp_string(ts);
	if (capture_len < sizeof(struct ethhdr))
	{
		fprintf(stderr, "Packet with timestamp %s is too short and does not contain all details", output->ts);
		return;
	}
	
	// Parse ethernet part
	const struct ethhdr *ethernet = (struct ethhdr*)(packet);
	if(!ethernet)
		return;
	
	output->src_MAC = bin_to_strhex(ethernet->h_source, sizeof(ethernet->h_source),':');
	output->dest_MAC = bin_to_strhex(ethernet->h_dest, sizeof(ethernet->h_dest),':');
	output->packet_len = capture_len;

	u_short type = ntohs(ethernet->h_proto);

	//check for packet type
	if(type == ETHERTYPE_IP)
	{
		output->h_proto = "IPv4";
		//Parse IP part
		ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
		if(!ip)
			return;
		unsigned short iphdrlen = ip->ihl*4;
		if (iphdrlen < 20) 
		{
			printf("   * Invalid IP header length: %u bytes\n", size_ip);
			return;
		}
		inet_ntop(AF_INET,&(ip->saddr),output->src_IP,sizeof(output->src_IP));
		inet_ntop(AF_INET,&(ip->daddr),output->dst_IP,sizeof(output->dst_IP));
		switch (ip->protocol) //Check the Protocol and do accordingly...
	    {
	        case 1:  //ICMP Protocol
	            output->ip_proto = "ICMP";
	            break;
	         
	        case 2:  //IGMP Protocol
	            output->ip_proto = "IGMP";
	            break;
	         
	        case 6:  //TCP Protocol
	            output->ip_proto = "TCP";
	            break;
	         
	        case 17: //UDP Protocol
	            output->ip_proto = "UDP";
	            break;
	         
	        default: //Some Other Protocol
	            break;
	    }

		//Parse TCP part
		struct tcphdr *tcp=(struct tcphdr*)(packet + iphdrlen + sizeof(struct ethhdr));
		if(!tcp)
			return;
		int tcp_size =  tcp->doff*4;
		int total_header = sizeof(struct ethhdr) + iphdrlen + tcp_size;
		if (total_header < 20) 
		{
			printf("   * Invalid TCP header length: %u bytes\n", total_header);
			return;
		}

		output->sport = ntohs(tcp->source);
		output->dport = ntohs(tcp->dest);
		char* bin_pay_load = (char*)(packet + total_header);
		int size_payload = ntohs(ip->tot_len) - (iphdrlen + tcp_size);
		printPacket = true;
		if(size_payload <= 0 || (args_orig->matching_string && !strstr(bin_pay_load, args_orig->matching_string)))
		{
			printPacket = false;
		}
		else
		{
			output->pay_load = bin_pay_load;
			output->pay_load_length = size_payload;
		}
	}
	//packet is Ethernet type
	else if(type == ETHERTYPE_ARP)
	{
		struct sniff_arphdr *arp = (struct sniff_arphdr*)(packet + sizeof(struct ethhdr));
		if(!arp)
			return;
		output->src_IP_ARP = bin_to_strdecimal(arp->spa, sizeof(arp->spa));
		output->dst_IP_ARP = bin_to_strdecimal(arp->tpa, sizeof(arp->tpa));
		output->h_proto = "ARP";
		printPacket = true;
	}

	if(printPacket)
		printOutputPacket(output);
	
	return;
}
int sniffLiveConnection(command_line_args* args)
{
	
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 mask;		
	bpf_u_int32 net;		
	struct bpf_program fp;	
	const u_char *packet;	
	struct pcap_pkthdr header;
	if(args->interface == 0)
		args->interface = pcap_lookupdev(errbuf);
	
	if (args->interface == NULL) 
	{
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		net = 0;
    	mask = 0;
		return(2);
	}
	else
	{
		printf("Listening on the interface %s\n", args->interface);
	}

	memset(errbuf, 0, PCAP_ERRBUF_SIZE);
	if (pcap_lookupnet(args->interface, &net, &mask, errbuf) == -1) 
	{
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", args->interface, errbuf);
		net = 0;
		mask = 0;
	}
	
	//Assign handle to the packet connection
	pcap_t *handle = pcap_open_live(args->interface, BUFSIZ, 1, 0, errbuf);
	if (handle == NULL) 
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", args->interface, errbuf);
		return(2);
	}

	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, args->filter_exp, 0, net) == -1) 
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n", args->filter_exp, pcap_geterr(handle));
		return(2);
	}
	
	if (pcap_setfilter(handle, &fp) == -1) 
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", args->filter_exp, pcap_geterr(handle));
		return(2);
	}
	
	pcap_loop(handle, -1, parsePacket, (u_char*) args);
	pcap_freecode(&fp);
	pcap_close(handle);
	/* Grab a packet */
	//packet = pcap_next(handle, &header);
	//parsePacket(args->matching_string, &header,packet);

	//pcap_close(handle);
	return 0;
}

//Convert the epoch seconds to DateTime value
const char *timestamp_string(struct timeval ts)
{
	static char timestamp_string_buf[256];

	char* fmt = "%Y-%m-%d %H:%M:%S";
	
	time_t t;
	struct tm *tmp;

	t = (time_t)((int) ts.tv_sec);
	tmp = localtime(&t);
	if (tmp == NULL) 
	{
		perror("localtime");
		exit(EXIT_FAILURE);
	}

	if (strftime(timestamp_string_buf, sizeof(timestamp_string_buf), fmt, tmp) == 0)
	{
		fprintf(stderr, "strftime returned 0");
		exit(EXIT_FAILURE);
	}
	sprintf(timestamp_string_buf, "%s.%06d", timestamp_string_buf, (int) ts.tv_usec);
	return timestamp_string_buf;
}

//Convert Byte array to Hexadecimal string for MAC Address 
char* bin_to_strhex(const u_char *bin, unsigned int binsz, char delim)
{
	char hex_str[]= "0123456789abcdef";
  	unsigned int  i;

  	//static char mac_address[18];// = (char*)malloc(2 * binsz + 1);
  	char *mac_address = (char *)malloc(binsz * 3);
  	if (!binsz)
    	return "";

  	for (i = 0; i < binsz; i++)
	{
	  mac_address[i * 3 + 0] = hex_str[(bin[i] >> 4) & 0x0F];
	  mac_address[i * 3 + 1] = hex_str[(bin[i]) & 0x0F];
	  mac_address[i * 3 + 2] = delim;
	}
	mac_address[binsz * 3 - 1] = 0;
	return mac_address;
}

//Convert Byte array to decimal string for IP Address
char* bin_to_strdecimal(const u_char *bin, unsigned int binsz)
{
	char* ip_address = (char*)malloc(sizeof(char));
	int length = 0;
	for(int i = 0; i < binsz; i++)
	{
		length += sprintf(ip_address + length, "%d.", (int)bin[i]);
	}
	ip_address[length - 1] = 0;
	return ip_address;
}

//Print the pay load in a presentable format
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;
	int line_len;
	int offset = 0;
	const u_char *ch = payload;

	if (len <= 0)
		return;

	if (len <= line_width) 
	{
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	
	while(true)
	{
	
		line_len = line_width % len_rem;
	
		print_hex_ascii_line(ch, line_len, offset);
	
		len_rem = len_rem - line_len;
	
		ch = ch + line_len;
	
		offset = offset + line_width;
	
		if (len_rem <= line_width)
		{		
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}
void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	printf("%05d   ", offset);
	
	ch = payload;
	for(i = 0; i < len; i++) 
	{
		printf("%02x ", *ch);
		ch++;
		if (i == 7)
			printf(" ");
	}

	if (len < 8)
		printf(" ");

	if (len < 16) 
	{
		gap = 16 - len;
		for (i = 0; i < gap; i++) 
		{
			printf("   ");
		}
	}
	printf("   ");
	
	ch = payload;
	for(i = 0; i < len; i++) 
	{
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");
	return;
}