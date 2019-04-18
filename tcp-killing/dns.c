#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <time.h>

#include "dns.h"


int parse_dns_query_hijack(uint8_t *buf, query *q)
{

	dns_header *dns = NULL;
	dns = (dns_header *)buf;

	uint8_t *p;
	p = &buf[sizeof(dns_header)]; //jump over the dns header

	if (ntohs(dns->qd_count) > 0)
	{

		uint8_t qname[HOST_NAME_SIZE];
		int position = 0;
		get_domain_name(p, buf, qname, &position);
		q->qname = malloc(HOST_NAME_SIZE);
		memset(q->qname, 0, HOST_NAME_SIZE);
		strncpy((char *)(q->qname), (char *)qname, strlen((char *)qname));

		p += position + 1;
		q->ques = (question *)p;
	}

	return ntohs(dns->id);
}

void get_domain_name(uint8_t *p, uint8_t *buff, uint8_t *name, int *position)
{
	// this function is improved by Pierre-Jean.
	// true if the buffer uses compression (see below)
	bool compressed = false;

	int i = 0;

	// real length of the buffer, that is if we use compression,
	// the length will be smaller
	//     eg. 01 62 c0 5f will have buffer_len 4
	//         but the actual host_name is longer, because
	//         we use compression and concatenate what is
	//         at position 5f immediatly after 01 62
	int buffer_len = -1;

	while (*p != 0)
	{
		// the rest of the chain points to somewhere else
		if ((*p & 0xc0) == 0xc0)
		{
			//	The pointer takes the form of a two octet sequence:
			//
			//	    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
			//	    | 1  1|                OFFSET                   |
			//	    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
			//
			//	The first two bits are ones. The OFFSET field specifies an offset from
			//	the start of the message (i.e., the first octet of the ID field in the
			//	domain header).

			uint16_t offset = ntohs(*((uint16_t *)p)) & 0x3fff;
			p = buff + offset;
			compressed = true;

			// +2 comes from c0 xx, where xx is the address
			// the pointer points to
			buffer_len = i + 2;
		}
		uint8_t num = *((uint8_t *)p);
		strncpy((char *)(name + i), (char *)(p + 1), num);
		p += (num + 1);
		i += num;
		strncpy((char *)(name + i), ".", 1);
		i++;
	}
	*(name + i) = '\0';

	// +1 because we take into account the nul length end character,
	// which is not present when using a pointer (ie. when we use
	// compression). Indeed, the pointer points to a chain already
	// ending by the \0 char
	if (compressed == false)
		buffer_len = i + 1;

	// position can change both when there is compression
	// and when there is not. Thus, use not_compressed_len to see
	// if we moved forward in the chain
	if (buffer_len > 0)
		*position = buffer_len;
}

void get_dns_name(uint8_t *dns, uint8_t *host)
{
	char host_cp[HOST_NAME_SIZE];
	strncpy(host_cp, (char *)host, HOST_NAME_SIZE);

	//	printf("host name: %s\n", host_cp);
	char *tk;
	tk = strtok(host_cp, ".");
	int i = 0;
	while (tk != NULL)
	{
		//		sprintf(length, "%lu", strlen(tk));
		*(dns + i) = (uint8_t)(strlen(tk)); //set the number of chars in the label

		i++;
		strncpy((char *)(dns + i), tk, strlen(tk)); //the label

		i += strlen(tk);
		tk = strtok(NULL, ".");
	}
	*(dns + i) = '\0';
}


void build_dns_header(dns_header *dns, int id, int query, int qd_count,
					  int an_count, int ns_count, int ar_count)
{
	srand(time(NULL));

	if (id == 0)
		dns->id = (uint16_t)htons(rand()); //set a random id
	else
		dns->id = (uint16_t)htons(id);

	dns->qr = query; //query
	dns->opcode = 0; //standard query
	dns->aa = 0;	 //no aa
	dns->tc = 0;	 //not truncated
	dns->rd = 1;	 //recursion desired

	dns->ra = 0; //recursion not available
	dns->z = 0;  //must be 0
	dns->ad = 0;
	dns->cd = 0;
	dns->rcode = 0; //no error condition

	dns->qd_count = htons(qd_count); //  question
	dns->an_count = htons(an_count); //answer
	dns->ns_count = htons(ns_count); //authenticate
	dns->ar_count = htons(ar_count); //additional
}

void build_name_section(uint8_t *qname, char *host_name, int *position)
{
	get_dns_name(qname, (uint8_t *)host_name);
	*position = strlen((char *)qname) + 1; //calculate the offset
										   
}
