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

#define IPV4_ADDR_LEN 4
#define IPV6_ADDR_LEN 16
#define ETH_ADDR_LEN 6

typedef struct eth2 {
    u_char src [ETH_ADDR_LEN];
    u_char dest [ETH_ADDR_LEN];
    u_short type;
} eth2;

typedef struct ipv4_header
{
    u_char v_ihl;
    u_char dscp_ecn;
    u_short length;
    
    u_short id;

    u_char flags_fragoffset[2];
    u_char ttl;
    u_char proto;

    u_char header_checksum[2];

    u_char src_ip[IPV4_ADDR_LEN];
    u_char dst_ip[IPV4_ADDR_LEN];
    
    u_char * options;
    u_int16_t options_size;
} ipv4_header;
#define IPV4_IHL(header) (((header)->v_ihl) & 0x0f)

typedef struct ipv6_header
{
    u_char ver_class_label[4];

    u_short length;

    u_char proto;
    u_char hop_limit;

    u_char src_ip[IPV6_ADDR_LEN];
    u_char dst_ip[IPV6_ADDR_LEN];
} ipv6_header;

typedef struct ip_header
{    
    union
    {
        ipv4_header *ipv4;
        ipv6_header *ipv6;
    };

    u_short type;
} ip_header;

typedef struct udp_header
{
    u_short src_port;
    u_short dst_port;
    u_short length;
    u_char checksum[2];
} udp_header;

typedef struct tcp_header
{
    u_short src_port;
    u_short dst_port;

    u_int32_t seqno;
    u_int32_t ackno;
    
    union 
    {
        u_short flags;
        u_char flags_bytes [2];
    };
    
    u_short window_size;

    u_char checksum[2];
    u_char urgent[2];

    u_char * options;
    u_int16_t options_size;
} tcp_header;
#define TCP_OFF(header) ((((header)->flags_bytes[0]) & 0xf0) >> 4)
#define TCP_NS(header) (((header)->flags_bytes[0]) & 0x01)
#define TCP_SWR(header) ((((header)->flags_bytes[1]) & 0x80) >> 7)
#define TCP_ECE(header) ((((header)->flags_bytes[1]) & 0x40) >> 6)
#define TCP_URG(header) ((((header)->flags_bytes[1]) & 0x20) >> 5)
#define TCP_ACK(header) ((((header)->flags_bytes[1]) & 0x10) >> 4)
#define TCP_PSH(header) ((((header)->flags_bytes[1]) & 0x08) >> 3)
#define TCP_RST(header) ((((header)->flags_bytes[1]) & 0x04) >> 2)
#define TCP_SYN(header) ((((header)->flags_bytes[1]) & 0x02) >> 1)
#define TCP_FIN(header) (((header)->flags_bytes[1]) & 0x01)

typedef struct proto_header
{
    union
    {
        udp_header *udp;
        tcp_header *tcp;
    };

    u_char type;
} proto_header;

typedef struct flow
{
    u_short type;
    
    union
    {
        u_char ipv4[IPV4_ADDR_LEN];
        u_char ipv6[IPV6_ADDR_LEN];
    } src;

    union
    {
        u_char ipv4[IPV4_ADDR_LEN];
        u_char ipv6[IPV6_ADDR_LEN];
    } dst;

    u_short src_port;
    u_short dst_port;

    u_char proto;
} flow;


static bool running = true;


void signal_handler(int sig_num)
{
    signal(SIGINT, signal_handler);
    running = false;
}

void print_ipaddr(u_char *ip, u_short type)
{
    if (type == ETH_TYPE_IPV4)
    {
        for (size_t i = 0; i < IPV4_ADDR_LEN; i++)
        {
            if (i == 3)
            {
                printf("%03hhu", ip[i]);
            }
            else
            {
                printf("%03hhu:", ip[i]);
            }
        }
    }
    else
    {
        for (size_t i = 0; i < IPV6_ADDR_LEN; i++)
        {
            if (i % 2 != 0 && i != IPV6_ADDR_LEN - 1)
            {
                printf("%02x:", ip[i]);
            }
            else
            {
                printf("%02x", ip[i]);
            }
        }
    }
}

void usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-i <device name>, Start packet capture from device with <device name> untill control+c is pressed\n"
		   "-r <file name>, Use pcap file with <file name> as input.\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}

size_t get_ip_header_length(ip_header *header)
{
    if (header->type == ETH_TYPE_IPV6)
    {
        return sizeof(ipv6_header);
    }
    else
    {
        return IPV4_IHL(header->ipv4) * 4;
    }
}

size_t get_proto_header_length(proto_header *header)
{
    if (header->type == PROTO_UDP)
    {
        return sizeof(udp_header);
    }
    else
    {
        return TCP_OFF(header->tcp) * 4;
    }
}

void populate_flow(flow * f, ip_header * ip, proto_header *proto)
{
    f->type = ip->type;
    f->proto = proto->type;
    
    if (proto->type == PROTO_UDP)
    {
        f->dst_port = ntohs(proto->udp->dst_port);
        f->src_port = ntohs(proto->udp->src_port);
    }
    else
    {
        f->dst_port = ntohs(proto->tcp->dst_port);
        f->src_port = ntohs(proto->tcp->src_port);
    }

    if (ip->type == ETH_TYPE_IPV4)
    {
        memcpy(&(f->src), ip->ipv4->src_ip, IPV4_ADDR_LEN);
        memcpy(&(f->dst), ip->ipv4->dst_ip, IPV4_ADDR_LEN);
    }
    else
    {
        memcpy(&(f->src), ip->ipv6->src_ip, IPV6_ADDR_LEN);
        memcpy(&(f->dst), ip->ipv6->dst_ip, IPV6_ADDR_LEN);
    }
}

flow* swap_flow_src_dst(flow *f)
{
    u_char tmp_addr[IPV6_ADDR_LEN];
    u_short tmp_port;

    tmp_port = f->dst_port;
    memcpy(tmp_addr, &(f->dst), IPV6_ADDR_LEN);

    f->dst_port = f->src_port;
    memcpy(&(f->dst), &(f->src), IPV6_ADDR_LEN);

    f->src_port = tmp_port;
    memcpy(&(f->src), tmp_addr, IPV6_ADDR_LEN);

    return f;
}

int insert_flow_if_unique(flow *f, flow ***array, long *size)
{
    for (long i = 0; i < *size; i++)
    {
        if (memcmp(f, (*array)[i], sizeof(flow)) == 0)
        {
            return i;
        }
        // else
        // {
        //     if (memcmp(swap_flow_src_dst(f), (*array)[i], sizeof(flow)) == 0)
        //     {
        //         return i;
        //     }
        //     swap_flow_src_dst(f);
        // }
    }
    
    *size += 1;
    *array = (flow **)realloc(*array, (*size)*sizeof(flow *));
    (*array)[(*size) - 1] = f;

    return (*size) - 1;
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

    flow ** flows_detected = NULL;
    long flow_count = 0;

    u_int32_t * nextexp_seq = NULL;
    long seq_count = 0;

    long total_packet_count = 0;
    long tcp_packet_count = 0;
    long udp_packet_count = 0;

    long tcp_bytes_received = 0;
    long udp_bytes_received = 0;

    printf("IP Src\tIP Dst\tPort Src\tPort Dst\tProtocol\tHeader len\tPayload len\tRetransmitted\n");

    while (((ret = pcap_next_ex(handle, &header, &packet)) == 1) &&
            running)
    {
        eth2 * eth2_frame = (eth2 *)packet;
        ip_header ip_frame = {0};
        proto_header proto_frame = {0};
        flow * f = (flow *)calloc(1, sizeof(flow));

        ip_frame.ipv4 = (ipv4_header*)(packet + sizeof(eth2));
        if (ntohs(eth2_frame->type) == ETH_TYPE_IPV4)
        {
            ip_frame.type = ETH_TYPE_IPV4;
            proto_frame.type = ip_frame.ipv4->proto;
        }
        else if (ntohs(eth2_frame->type) == ETH_TYPE_IPV6)
        {
            ip_frame.type = ETH_TYPE_IPV6;
            proto_frame.type = ip_frame.ipv6->proto;
        }

        size_t ip_header_len = get_ip_header_length(&ip_frame);
        proto_frame.tcp = (tcp_header *)(packet + sizeof(eth2) + ip_header_len);
        if (proto_frame.type == PROTO_TCP || proto_frame.type == PROTO_UDP)
        {
            populate_flow(f, &ip_frame, &proto_frame);

            int id = insert_flow_if_unique(f, &flows_detected, &flow_count);

            if (seq_count != flow_count)
            {
                seq_count = flow_count;
                nextexp_seq = realloc(nextexp_seq, sizeof(u_int32_t)*seq_count);
                
                if (proto_frame.type == PROTO_TCP)
                {
                    nextexp_seq[id] = ntohl(proto_frame.tcp->seqno);
                }
                else
                {
                    nextexp_seq[id] = 0;
                }
            }

            print_ipaddr((f->src.ipv4), f->type);
            printf(" ");
            print_ipaddr((f->dst.ipv4), f->type);

            printf(" %hu %hu ", f->src_port, f->dst_port);

            size_t proto_header_len = get_proto_header_length(&proto_frame);
            size_t payload_len = header->len - (sizeof(eth2) + ip_header_len + proto_header_len);

            if (header->len == 60)
            {
                proto_header_len += payload_len;
                payload_len = 0;
            }

            bool retransmitted = false;
            if (proto_frame.type == PROTO_UDP)
            {
                udp_packet_count++;
                udp_bytes_received += header->len;

                printf("UDP");
            }
            else
            {
                tcp_packet_count++;
                tcp_bytes_received += header->len;

                printf("TCP");

                // TODO Retransmited
                proto_frame.tcp->seqno = ntohl(proto_frame.tcp->seqno);
                proto_frame.tcp->flags = ntohs(proto_frame.tcp->flags);

                if ((payload_len > 0 || (TCP_SYN(proto_frame.tcp) || TCP_FIN(proto_frame.tcp))) &&
                    proto_frame.tcp->seqno < nextexp_seq[id])
                {
                    retransmitted = true;
                }
                else
                {
                    nextexp_seq[id] = proto_frame.tcp->seqno + payload_len;

                    if ((proto_frame.tcp->flags & 0x0fff) == 0x0002 ||
                        (proto_frame.tcp->flags & 0x0fff) == 0x0012 ||
                        (proto_frame.tcp->flags & 0x0fff) == 0x0011)
                    {
                        nextexp_seq[id]++;
                    }
                }
            }

            printf(" %ld %ld ", proto_header_len, payload_len);

            if (retransmitted)
            {
                printf("Yes");
            }
            else
            {
                printf("No");
            }

            printf("\n");
        }

        total_packet_count++;
    }

    if (ret == -1)
    {
        pcap_perror(handle, "Error getting next packet: ");
    }

    long tcp_flows = 0;
    long udp_flows = 0;
    for (long i = 0; i < flow_count; i++)
    {
        if (flows_detected[i]->proto == PROTO_UDP)
        {
            udp_flows++;
        }
        else
        {
            tcp_flows++;
        }
    }

    printf("\nTotal Flows\tTCP Flows\tUDP Flows\tTotal Packets\tTCP Packets\tUDP Packets\tTCP Bytes\tUDP Bytes\n");
    printf("%ld\t\t%ld\t\t%ld\t\t%ld\t\t%ld\t\t%ld\t\t%ld\t\t%ld\n",
            flow_count,
            tcp_flows,
            udp_flows, 
            total_packet_count,
            tcp_packet_count,
            udp_packet_count,
            tcp_bytes_received,
            udp_bytes_received);

    pcap_close(handle);
    return 0;
}

/*

Source IP | Destination IP | Source Port | Destination Port | Protocol | Header Length | Payload Length | Retransmitted

At the end

Total flows | TCP flows count | UDP flows count | Total packets received | Total TCP packets | Total UDP packets | Total TCP bytes | Total UDP bytes

*/