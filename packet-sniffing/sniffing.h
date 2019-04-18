#define BUF_SIZE 65536

#define LINKTYPE_NULL 0
#define LINKTYPE_ETH 1
#define LINKTYPE_WIFI 127

static int HEADER_TYPE; //set by select_device()

//Some parameters for the user :
const char FILTER[] = "udp && (dst port 53)"; //the expression of the filter

#define TIME_OUT 1 //the timeout for processing packets in ms

#define SET_PROMISC 1 //set to 1 to put the device in monitoring mode

#define NUMBER_OF_PACKETS_TO_SNIFF -1 //set the number of packet that will be sniffed, put -1 to loop

/*
*   Main loop to process the received packets
*
*/

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);

/*
*   Create the handle relevant to the device name
*
*/

pcap_t *create_handle(char *dev_name);

/*
*   Set the filter chosen in FILTER
*
*/

void set_filter(pcap_t *handle, char *dev_name);

/*
*   Select a device and set the correct HEADER_TYPE
*   return the name of the chosen device minus the '\0' at the end
*/

char *select_device();