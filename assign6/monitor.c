#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>

#define ETH_TYPE_IPV4 0x0800
#define ETH_TYPE_IPV6 0x86DD

#define PROTO_UDP 0x11
#define PROTO_TCP 0x06

typedef struct eth2 {
    u_char src [6];
    u_char dest [6];
    union
    {
        u_char type_bytes [2];
        u_short type;
    };
} eth2;

typedef struct ipv4_header
{
    u_char version_ihl;
    u_char dscp_ecn;
    union
    {
        u_short length;
        u_char length_bytes[2];
    };
    
    union
    {
        u_short id;
        u_char id_bytes[2];
    };

    u_char flags_fragoffset[2];
    u_char ttl;
    u_char proto;

    u_char header_checksum[2];

    u_char src_ip[4];
    u_char dst_ip[4];
} ipv4_header;

typedef struct ipv6_header
{
    u_char ver_class_label[4];

    union
    {
        u_short length;
        u_char length_bytes[2];
    };

    u_char proto;
    u_char hop_limit;

    u_char src_ip[16];
    u_char dst_ip[16];
} ipv6_header;

typedef struct udp_header
{
    union
    {
        u_short src_port;
        u_char src_port_bytes[2];
    };
    
    union
    {
        u_short dst_port;
        u_char dst_port_bytes[2];
    };

    union
    {
        u_short length;
        u_char length_bytes[2];
    };

    u_char checksum[2];
} udp_header;

typedef struct tcp_header
{
    
} tcp_header;

static bool running = false;

void signal_handler(int sig_num)
{
    signal(SIGINT, signal_handler);
    running = true;
}

/*
 * Prints the hex value of the input
 * 16 values per line
 */
void print_hex(u_char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}

bool compare_array(u_char *arr1, u_char *arr2, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        if (arr1[i] != arr2[i])
        {
            return false;
        }
    }

    return true;
}

void usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-i <device name>, \n"
		   "-r <file name>, \n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}

int main(int argc, char *argv[])
{
    signal(SIGINT, signal_handler);

    int ch;
    char * dev_name = NULL;
    char * file_name = NULL;

    bool devmode = false;

    while ((ch = getopt(argc, argv, "hi:r:")) != -1)
    {
        switch (ch)
        {
            case 'i':
            {
                dev_name = strdup(optarg);
                devmode = true;
            }break;
            case 'r':
            {
                file_name = strdup(optarg);
            }break;
            default:
            {
                usage();
            }break;
        }
    }

    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    pcap_t *handle;

    if (devmode)
    {
        handle = pcap_open_live(dev_name, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL)
        {
            fprintf(stderr, "Could not open device %s: %s\n", dev_name, errbuf);
            return 2;
        }
    }
    else
    {
        handle = pcap_open_offline(file_name, errbuf);
        if (handle == NULL)
        {
            fprintf(stderr, "Could not open file %s: %s\n", dev_name, errbuf);
            return 2;
        }
    }
    

    if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev_name);
		return(2);
	}

    struct pcap_pkthdr *header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
    int ret = 0;

    int count = 0;
    while (((ret = pcap_next_ex(handle, &header, &packet)) == 1) &&
            !running)
    {
        eth2 * eth2_frame = (eth2 *)packet;
        if (ntohs(eth2_frame->type) == ETH_TYPE_IPV4)
        {
            printf("IPV4\n");
        }
        else if (ntohs(eth2_frame->type) == ETH_TYPE_IPV6)
        {
            printf("IPV6\n");
        }
        
        count++;
    }

    printf("Got %d packets\n", count);

    if (ret == -1)
    {
        pcap_perror(handle, "Error getting next packet: ");
    }

    pcap_close(handle);
    return 0;
}