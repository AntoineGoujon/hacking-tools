#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "header.h"

#define SRC_IP "129.14.96.160" //set your source ip here. It can be a fake one
#define SRC_PORT 5555			//set the source port here. It can be a fake one

#define DEST_IP "129.104.96.160"		//set your destination ip here
#define DEST_PORT 5555			//set the destination port here
#define TEST_STRING "test data" //a test string as packet payload

int main(int argc, char *argv[])
{
	char source_ip[] = SRC_IP;
	char dest_ip[] = DEST_IP;

	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	int hincl = 1; /* 1 = on, 0 = off */
	setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));

	if (fd < 0)
	{
		perror("Error creating raw socket ");
		exit(EXIT_FAILURE);
	}

	char packet[65536], *data;
	char data_string[] = TEST_STRING;
	memset(packet, 0, 65536);

	//IP header pointer
	struct iphdr *iph = (struct iphdr *)packet;

	//UDP header pointer
	struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
	struct pseudo_udp_header psh; //pseudo header

	//data section pointer
	data = packet + sizeof(struct iphdr) + sizeof(struct udphdr);

	//fill the data section
	strncpy(data, data_string, strlen(data_string));

	//fill the IP header here
	iph->version = 4;
	iph->ihl = 5;
	iph->tos = 0;
	iph->frag_off = 0;
	iph->ttl = 150;
	iph->protocol = 17;
	iph->check = 0;
	iph->saddr = inet_addr(source_ip);
	iph->daddr = inet_addr(dest_ip);
	iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + strlen(data));
	iph->id = 0;

	iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));

	//fill the UDP header
	udph->source = htons(SRC_PORT);
	udph->dest = htons(DEST_PORT);
	udph->len = htons(sizeof(struct udphdr) + strlen(data));
	udph->check = 0;

	//fill the UDP pseudo header

	memset(&psh, 0, sizeof(struct pseudo_udp_header));

	psh.dest_address = inet_addr(dest_ip);
	psh.source_address = inet_addr(source_ip);
	psh.protocol = 17;
	psh.udp_length = htons(sizeof(struct udphdr) + strlen(data));
	psh.placeholder = 0;

	//filling UDP header checksum

	char *checkstr;
	checkstr = malloc(sizeof(struct pseudo_udp_header) + sizeof(struct udphdr) + strlen(data));

	memcpy(checkstr, (char *)&psh, sizeof(struct pseudo_udp_header));
	memcpy(checkstr + sizeof(struct pseudo_udp_header), (char *)udph, sizeof(struct udphdr));
	memcpy(checkstr + sizeof(struct pseudo_udp_header) + sizeof(struct udphdr), data, strlen(data));

	udph->check = checksum((unsigned short *)checkstr, sizeof(struct pseudo_udp_header) + sizeof(struct udphdr) + strlen(data));

	//send the packet

	struct sockaddr_in to;
	memset(&to, '0', sizeof(struct sockaddr_in));
	to.sin_family = AF_INET;
	inet_pton(AF_INET, dest_ip, &(to.sin_addr));
	to.sin_port = htons(DEST_PORT);

	int sizeofpacket = sizeof(struct iphdr) + sizeof(struct udphdr) + strlen(data);
	int i = 0;
	while (i<100)
	{
		int n = sendto(fd, packet, sizeofpacket, 0, (struct sockaddr *)&to, sizeof(struct sockaddr));
		if (n < 0)
		{
			perror("Error sending the packet");
			return -1;
		}

		printf("%d bytes sent successfully \n", n);
		i++;
	}
	return 0;
}