#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>

// Signiture of funtions
unsigned short in_cksum(unsigned short *buf, int length);

/* IP Header */
struct ipheader
{
    unsigned char iph_ihl : 4,       // IP header length
        iph_ver : 4;                 // IP version
    unsigned char iph_tos;           // Type of service
    unsigned short int iph_len;      // IP Packet length (data + header)
    unsigned short int iph_ident;    // Identification
    unsigned short int iph_flag : 3, // Fragmentation flags
        iph_offset : 13;             // Flags offset
    unsigned char iph_ttl;           // Time to Live
    unsigned char iph_protocol;      // Protocol type
    unsigned short int iph_chksum;   // IP datagram checksum
    struct in_addr iph_sourceip;     // Source IP address
    struct in_addr iph_destip;       // Destination IP address
};

/* UDP Header */
struct udpheader
{
    u_int16_t udp_sport; /* source port */
    u_int16_t udp_dport; /* destination port */
    u_int16_t udp_ulen;  /* udp length */
    u_int16_t udp_sum;   /* udp checksum */
};

struct tcpheader
{
    unsigned short source;    /* source port */
    unsigned short dest;      /* destination port */
    unsigned int seq;         /* sequence number */
    unsigned int ack_seq;     /* acknowledgement number */
    unsigned char th_off : 4; /* data offset */
    unsigned char th_x2 : 4;  /* (unused) */
    unsigned char th_flags;
#define TH_FIN 0x01    /* == 1*/
#define TH_SYN 0x02    /* == 2*/ 
#define TH_RST 0x04    /* == 4*/
#define TH_PUSH 0x08   /* == 8*/
#define TH_ACK 0x10    /* == 16*/
#define TH_URG 0x20    /* == 32*/
    unsigned short th_win; /* window */
    unsigned short th_sum; /* checksum */
    unsigned short th_urp; /* urgent pointer */
};

struct icmpheader
{
    unsigned char icmp_type;        // ICMP message type
    unsigned char icmp_code;        // Error code
    unsigned short int icmp_chksum; // Checksum for ICMP Header and data
    unsigned short int icmp_id;     // Used for identifying request
    unsigned short int icmp_seq;    // Sequence number
};

/*************************************************************
  Given an IP packet, send it out using a raw socket.
**************************************************************/
void send_raw_ip_packet(struct ipheader *ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
               &enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: Send the packet out.
    sendto(sock, ip, ntohs(ip->iph_len), 0,
           (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}
struct ipheader *tcp_packet()
{
    char buffer[1500];

    memset(buffer, 0, 1500);
    struct ipheader *ip = (struct ipheader *)buffer;
    struct tcpheader *tcp = (struct tcpheader *)(buffer + sizeof(struct ipheader));
    ip->iph_ver = 4;
    ip->iph_ihl = 5;
    ip->iph_ttl = 20;
    ip->iph_sourceip.s_addr = inet_addr("192.168.149.128");
    ip->iph_destip.s_addr = inet_addr("192.168.149.128");

    /*********************************************************
       Step 1: Fill in the TCP data field.
     ********************************************************/
    char *data = buffer + sizeof(struct ipheader) +
                 sizeof(struct udpheader);
    const char *msg = "Hey there, try to find me.\n";
    int data_len = strlen(msg);
    strncpy(data, msg, data_len);

    /*********************************************************
       Step 2: Fill in the TCP header.
     ********************************************************/
    tcp->source = htons(8888);
    tcp->dest = htons(8889);
    tcp->seq = 10;
    tcp->ack_seq = 0;
    tcp->th_flags = 16;
    tcp->th_win = htons(1127);
    tcp->th_sum = 0;
    tcp->th_off = 0;
    tcp->th_urp = 0;
    /*********************************************************
       Step 3: Fill in the IP header.
     ********************************************************/

    ip->iph_protocol = IPPROTO_TCP; // The value is 17.
    ip->iph_len = htons(sizeof(struct ipheader) +
                        sizeof(struct tcpheader) + data_len);
    return ip;

}
struct ipheader *udp_packet()
{
    char buffer[1500];

    memset(buffer, 0, 1500);
    struct ipheader *ip = (struct ipheader *)buffer;
    struct udpheader *udp = (struct udpheader *)(buffer + sizeof(struct ipheader));
    ip->iph_ver = 4;
    ip->iph_ihl = 5;
    ip->iph_ttl = 20;
    ip->iph_sourceip.s_addr = inet_addr("192.168.149.128");
    ip->iph_destip.s_addr = inet_addr("192.168.149.128");

    /*********************************************************
       Step 1: Fill in the UDP data field.
     ********************************************************/
    char *data = buffer + sizeof(struct ipheader) +
                 sizeof(struct udpheader);
    const char *msg = "Hey there, try to find me.\n";
    int data_len = strlen(msg);
    strncpy(data, msg, data_len);

    /*********************************************************
       Step 2: Fill in the UDP header.
     ********************************************************/
    udp->udp_sport = htons(8888);
    udp->udp_dport = htons(8886);
    udp->udp_ulen = htons(sizeof(struct udpheader) + data_len);
    udp->udp_sum = 0; /* Many OSes ignore this field, so we do not
                         calculate it. */

    /*********************************************************
       Step 3: Fill in the IP header.
     ********************************************************/

    /* Code omitted here; same as that in (*@Listing~\ref{snoof:list:icmpecho}@*) */
    ip->iph_protocol = IPPROTO_UDP; // The value is 17.
    ip->iph_len = htons(sizeof(struct ipheader) +
                        sizeof(struct udpheader) + data_len);
    return ip;
}
struct ipheader *icmp_packet()
{
    char buffer[1500];
    memset(buffer, 0, 1500);

    /*********************************************************
      Step 1: Fill in the ICMP header.
    ********************************************************/
    struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));
    icmp->icmp_type = 0; // ICMP Type: 8 is request, 0 is reply.

    // Calculate the checksum for integrity
    icmp->icmp_chksum = 0;
    icmp->icmp_chksum = in_cksum((unsigned short *)icmp,
                                 sizeof(struct icmpheader));

    /*********************************************************
       Step 2: Fill in the IP header.
     ********************************************************/
    struct ipheader *ip = (struct ipheader *)buffer;
    ip->iph_ver = 4;
    ip->iph_ihl = 5;
    ip->iph_ttl = 20;
    ip->iph_sourceip.s_addr = inet_addr("192.168.149.128");
    ip->iph_destip.s_addr = inet_addr("192.168.149.128");
    ip->iph_protocol = IPPROTO_ICMP;
    ip->iph_len = htons(sizeof(struct ipheader) +
                        sizeof(struct icmpheader));

    return ip;
}

int main(int argc, char *argv[])
{
    char *type = NULL;
    /* check for capture device name on command-line */
    if (argc > 2 || argc < 2)
    {
        printf("There is a input error.\n");
        exit(1);
    }
    else
    {
        type = argv[1];
    }

    // Switching by type
    if (strcmp(type, "tcp") == 0)
    {   
        printf("TCP packet spoofed\n");
        struct ipheader *iph;
        iph = tcp_packet();
        send_raw_ip_packet(iph);
    
    }
    // Switching by type
    else if (strcmp(type, "udp") == 0)
    {
        printf("UDP packet spoofed\n");
        struct ipheader *iph;
        iph = udp_packet();
        send_raw_ip_packet(iph);
    }
    // Switching by type
    else if (strcmp(type, "icmp") == 0)
    {
        printf("ICMP packet spoofed\n");
        struct ipheader *iph;
        iph = icmp_packet();
        send_raw_ip_packet(iph);
    }

    return 0;
}

/**********************************************
 * Listing 12.9: Calculating Internet Checksum
 **********************************************/

unsigned short in_cksum(unsigned short *buf, int length)
{
    unsigned short *w = buf;
    int nleft = length;
    int sum = 0;
    unsigned short temp = 0;

    /*
     * The algorithm uses a 32 bit accumulator (sum), adds
     * sequential 16 bit words to it, and at the end, folds back all
     * the carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    /* treat the odd byte at the end, if any */
    if (nleft == 1)
    {
        *(u_char *)(&temp) = *(u_char *)w;
        sum += temp;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    return (unsigned short)(~sum);
}