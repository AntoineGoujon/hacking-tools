#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "header.h"
#include "sniffing.h"

//some global counter
int tcp = 0, udp = 0, icmp = 0, others = 0, igmp = 0, total = 0, i, j;

int main(int argc, char *argv[])
{

	//select a device
	char *dev_name = select_device();

	//create the handle
	pcap_t *handle = create_handle(dev_name);

	//set the filter
	set_filter(handle, dev_name);
	printf("Device %s is opened. Begin sniffing with filter %s...\n", dev_name, FILTER);

	//open the logfile
	logfile = fopen("log.txt", "w");
	if (logfile == NULL)
	{
		printf("Unable to create file.");
	}

	//Put the device in sniff loop
	pcap_loop(handle, NUMBER_OF_PACKETS_TO_SNIFF, process_packet, NULL);

	pclose(logfile);
	pcap_close(handle);

	return 0;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	//	printf("a packet is received! %d \n", total++);
	int size = header->len;
	++total;

	//Finding the beginning of IP header
	struct iphdr *in_iphr;

	switch (HEADER_TYPE)
	{
	case LINKTYPE_ETH:
		in_iphr = (struct iphdr *)(buffer + 14);
		size -= 14;
		break;

	case LINKTYPE_NULL:
		in_iphr = (struct iphdr *)(buffer + 4);
		size -= 4;
		break;

	case LINKTYPE_WIFI:
		in_iphr = (struct iphdr *)(buffer + 14);
		size -= 14;
		break;

	case DLT_LINUX_SLL:
		in_iphr = (struct iphdr *)(buffer + 16);
		size -= 16;
		break;

	default:
		printf("Unknown header type %d\n", HEADER_TYPE);
		exit(EXIT_FAILURE);
	}

	if (in_iphr->ihl != 5 || in_iphr->version != 4)
	{
		printf("Error parsing the packet");
		printf("Packet not processed");
		return;
	}

	switch (in_iphr->protocol) //Check the Protocol and do accordingly...
	{
	case 1: //ICMP Protocol
		++icmp;
		print_icmp_packet(buffer, size);
		break;

	case 2: //IGMP Protocol
		++igmp;
		break;

	case 6: //TCP Protocol
		++tcp;
		print_tcp_packet(buffer, size);
		break;

	case 17: //UDP Protocol
		++udp;
		print_udp_packet(buffer, size);
		break;

	default: //Some Other Protocol like ARP etc.
		++others;
		break;
	}

	printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\n", tcp, udp, icmp, igmp, others, total);
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

	//Setting timeout for processing packets to TIME_OUT
	if (pcap_set_timeout(handle, TIME_OUT))
		pcap_perror(handle, "Pcap set timeout error");

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