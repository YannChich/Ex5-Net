#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* don't fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len,FILE* filep);

void
print_hex_ascii_line(const u_char *payload, int len, int offset,FILE* filep);

void
print_app_usage(void);

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset,FILE* filep)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	fprintf(filep,"%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		fprintf(filep,"%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			fprintf(filep," ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		fprintf(filep," ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			fprintf(filep,"   ");
		}
	}
	fprintf(filep,"   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			fprintf(filep,"%c", *ch);
		else
			fprintf(filep,".");
		ch++;
	}

	fprintf(filep,"\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len,FILE* filep)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset,filep);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset,filep);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset,filep);
			break;
		}
	}

return;
}

//Fuction that retuns the packet flag

void print_flags(u_char flags,FILE* filep) {
    if (flags & TH_FIN) {
        fprintf(filep,"FIN ");
    }
    if (flags & TH_SYN) {
        fprintf(filep,"SYN ");
    }
    if (flags & TH_RST) {
        fprintf(filep,"RST ");
    }
    if (flags & TH_PUSH) {
        fprintf(filep,"PUSH ");
    }
    if (flags & TH_ACK) {
        fprintf(filep,"ACK ");
    }
    if (flags & TH_URG) {
        fprintf(filep,"URG ");
    }
    if (flags & TH_ECE) {
        fprintf(filep,"ECE ");
    }
    if (flags & TH_CWR) {
        fprintf(filep,"CWR ");
    }
}

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */

	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);

	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

	/* define/compute tcp header offset */
		tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
		size_tcp = TH_OFF(tcp)*4;
		if (size_tcp < 20) {
			printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
			return;
		}
	
	FILE* filep = fopen("315734616_341157501.txt","a");
	/* print source and destination IP addresses */
	fprintf(filep,"\n\n~~~~~~~~~~Packet number %d~~~~~~~~~~~~~~\n", count++);
	fprintf(filep,"\t Total packet size:%d\n",SIZE_ETHERNET+size_ip+size_tcp+size_payload);
	fprintf(filep,"~~~~~~~~~~~Ethernet HEADER~~~~~~~~~~~~~~\n");
	fprintf(filep,"[+] Source Address: %s\n", ethernet->ether_shost);
	fprintf(filep,"[+] Dest Address: %s\n", ethernet->ether_dhost);
	fprintf(filep,"[+] Type: %d (0x0800)\n", ethernet->ether_type);
	fprintf(filep,"~~~~~~~~~~~~~IP HEADER~~~~~~~~~~~~~~~~~~\n");
	fprintf(filep,"[+] Version: %u\n", (ip->ip_vhl >> 4) & 0xF);
	fprintf(filep,"[+] HEADER len:%u\n",(ip->ip_vhl & 0xF) * 4);
	fprintf(filep,"[+] Total len:%hu\n",ntohs(ip->ip_len));
	fprintf(filep,"[+] Identification:%hu\n",ntohs(ip->ip_id));
	fprintf(filep,"[>] Flags:\n");
	fprintf(filep,"  [-] Offset:%d\n",ip->ip_off);
	fprintf(filep,"  [-] TTL:%d\n",ip->ip_ttl);
	fprintf(filep,"  [-] Protocol:%d\n",ip->ip_p);
	fprintf(filep,"  [-] Checksum:%d\n",ntohs(ip->ip_sum));
	fprintf(filep,"[+] Source IP:%s\n",inet_ntoa(ip->ip_src));
	fprintf(filep,"[+] Dest IP:%s\n",inet_ntoa(ip->ip_dst));
	fprintf(filep,"~~~~~~~~~~~~~TCP HEADER~~~~~~~~~~~~~~~~~\n");
	fprintf(filep,"[+] Source port: %d\n", ntohs(tcp->th_sport));
	fprintf(filep,"[+] Dest port: %d\n", ntohs(tcp->th_dport));
	fprintf(filep,"[+] TCP seq len: %d\n", size_payload);
	fprintf(filep,"[+] Flags: ");
	print_flags(tcp->th_flags,filep);
	fprintf(filep,"\n");
	fprintf(filep,"[+] Window: %d\n", ntohs(tcp->th_win));
	fprintf(filep,"[+] Checksum: %d\n", ntohs(tcp->th_sum));
	

	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	if (size_payload > 0) {
		fprintf(filep,"[+] Payload (%d bytes):\n", size_payload);
		print_payload(payload, size_payload,filep);
	}
	fclose(filep);
	return;
}


int main(int argc, char **argv)
{

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "tcp";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = -1;			/* number of packets to capture */

	/* check for capture device name on command-line */
	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		exit(EXIT_FAILURE);
	}
	else {
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
	}
	//Head of the script.
	printf("Sniffing packets using '%s' interface with '%s' filter/s \n",dev,filter_exp);

	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\n[-] Capture complete.\n");

return 0;
}
