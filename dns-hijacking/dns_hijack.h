#ifndef PCAP_EXAMPLE_H_
#define PCAP_EXAMPLE_H_

#define BUF_SIZE 65536

int header_type;
#define LINKTYPE_NULL 0
#define LINKTYPE_ETH 1
#define LINKTYPE_WIFI 127

char *address_array = "163.172.6.103"; //the answer to put...



void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);


#endif /* PCAP_EXAMPLE_H_ */
