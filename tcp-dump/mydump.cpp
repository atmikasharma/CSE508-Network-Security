/*
 *
 *
 *  Created on: Oct 7, 2017
 *      Author: atmika
 */


/* SNIFFER PROGRAM */



#include<iostream>
#include<stdlib.h>
#include<stdio.h>
#include<pcap.h>
#include<unistd.h>
#include<ctype.h>
#include<string.h>
#include<errno.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<netinet/if_ether.h>
#include<net/ethernet.h>
#include<netinet/ether.h>
#include<sstream>
#include<time.h>

using namespace std ;

#define APP_NAME		"sniffex"
#define APP_DESC		"Sniffer example using libpcap"
#define APP_COPYRIGHT	"Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#define SNAP_LEN 1518

#define SIZE_ETHERNET 14

//#define ETHER_ADDR_LEN

const char *check_str ;

int head_len ;

u_char check_ip ;

char payload_check[10000] ;

u_char *payload_str ;

struct sniff_ethernet{

	u_char ether_dhost[ETHER_ADDR_LEN] ;	/* destination host address */

	u_char ether_shost[ETHER_ADDR_LEN] ;	/* source host address */

	u_short ether_type ;			/* IP, ARP, RARP etc. */

} ;

struct sniff_udp{
	u_short uh_sport ;
	
	u_short uh_dport ;

	u_short uh_ulen ;

	u_short uh_sum ;

} ;

struct sniff_ip{

	u_char ip_vhl ;				/* version << 4 | header lenth >> 2 */

	u_char ip_tos ;				/* type of service */

	u_short ip_len ;			/* total length */

	u_short ip_id ; 			/* identification */

	u_short ip_off ;			/* fragment offset flag */

	#define IP_RF 0x8000			/* reserved fragment flag */

	#define IP_DF 0x4000			/* dont fragment flag */

	#define IP_MF 0x2000			/* more fragments flag */

	#define IP_OFFMASK 0x1fff		/* mask for fragmenting */

	u_char ip_ttl ;				/* time to live */

	u_char ip_p ;				/* protocol */

	u_short ip_sum ;			/* checksum */

	struct in_addr ip_src, ip_dst ;		/* source and dest address */

} ;

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)


/* TCP header */

typedef u_int tcp_seq ;

struct sniff_tcp{
	u_short th_sport ;			/* source port */

	u_short th_dport ;			/* destination port */

	tcp_seq th_seq ;			/* sequence number */

	tcp_seq th_ack ;			/* acknowledgement number */

	u_char th_offx2 ;			/*data offset, rsvd */

#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)

	u_char th_flags ;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
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

int
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int
print_payload(const u_char *payload, int len);

int
print_hex_ascii_line(const u_char *payload, int len, int offset);

void
print_app_banner(void);

void
print_app_usage(void);

void string_match() ;

/*
 * app name/banner
 */
void
print_app_banner(void)
{

	cout<<APP_NAME<<" - "<<APP_DESC<<endl ;;
	cout<<APP_COPYRIGHT<<endl ;
	cout<<APP_DISCLAIMER<<endl ;

}

/*
 * print help text
 */
void
print_app_usage(void)
{

	cout<<"Usage: "<<APP_NAME<<" [interface]"<<endl ;
	cout<<"Options:"<<endl ;
	cout<<"    interface    Listen on <interface> for packets."<<endl ;

}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
int
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	//printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			cout<<"" ;
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		cout<<" " ;

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			cout<<"   " ;
		}
	}
	cout<<"   " ;

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return 0;
}

char *getTime(const struct pcap_pkthdr* header){
	stringstream ustream ;
	struct tm *timeInfo ;
	char buffer[80] ;
	timeInfo = localtime(&(header->ts.tv_sec)) ;
	strftime(buffer, 80,"%Y-%m-%d %X", timeInfo) ;
	strcat(buffer,".") ;
	ustream << header->ts.tv_usec ;
	strcat(buffer, ustream.str().c_str()) ;
	char *timeStamp = (char *)malloc(sizeof(buffer)) ;
	strcpy(timeStamp, buffer) ;
	cout<<timeStamp ;
	return(timeStamp) ;
}


/*
 * print packet payload data (avoid printing binary data)
 */
int print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return 0;

	/* data fits on one line */
	if (len <= line_width) {
		//snprintf(payload_check, len, ch) ;
		print_hex_ascii_line(ch, len, offset);
		return 0;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		//payload_check = snprintf(payload_check, line_len, ch) ;
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			//payload_check += snprintf(payload_check, len_rem, ch) ;
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return 0;
}


 void string_match(){

	int j=0 ;		
	for(int i = 0; i<(head_len); i++) {
		if(isprint(payload_str[i])){
			payload_check[j] = payload_str[i] ;
			j++ ;
		}
	}
}


/*
 * dissect/print packet
 */
int
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */

	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const struct sniff_udp *udp;		/* The UDP header */
	u_char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;
	int size_udp ;

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);

	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;

	/* set pointer to udp packet*/
	if(ip->ip_p == IPPROTO_UDP){
	udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip) ;
	size_udp = 8 ;

	/* define/compute udp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);

	/* compute udp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);

	}
	else{
	/* set the pointer to the tcp packet */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip) ;
	size_tcp = TH_OFF(tcp)*4 ;

	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	}
	
	check_ip = ip->ip_p ;
	head_len = size_payload ;
	payload_str = payload ;
	
	
	if(check_str != NULL ){
	string_match() ;
		if((size_payload > 0) && (strstr((char *)payload_check, check_str))!=NULL){
			count++;
			/* Get time stamp */
			cout<<endl ;
			char *timeStamp = getTime(header) ;

			cout<<" "  ;			
			
			printf("%s",(ether_ntoa((const struct ether_addr *)&ethernet->ether_shost)));
			cout<<" -> " ;

			printf("%s",(ether_ntoa((const struct ether_addr *)&ethernet->ether_dhost))) ;

			printf("type 0x%.4x ",ntohs(ethernet->ether_type)) ;

			
			/*cout<<"Packet number "<<count<<endl ;
			count++; */
 
			/*if (size_ip < 20) {
				printf("   * Invalid IP header length: %u bytes\n", size_ip);
				return 0;
			} */
		
			

			
			/* Get length of packet */

			cout<<"len "<<header->len<<endl ;

			
			
			if(ip->ip_p==IPPROTO_TCP){
				/* print source and destination IP addresses with port */
				printf("%s:%d -> %s:%d ", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport), inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport)) ;
				
			}
			if(ip->ip_p==IPPROTO_UDP){
				/* print source and destination IP addresses with port */
				printf("%s:%d -> %s:%d ", inet_ntoa(ip->ip_src), ntohs(udp->uh_sport), inet_ntoa(ip->ip_dst), ntohs(udp->uh_dport));
				
			}

			/* determine protocol */
			switch(ip->ip_p) {
				case IPPROTO_TCP:
					cout<<"TCP\n";
					break;
				case IPPROTO_UDP:
					cout<<"UDP\n";
					break;
				case IPPROTO_ICMP:
					cout<<"ICMP\n";
					break;
				case IPPROTO_IP:
					cout<<"IP\n";
					break;
				default:
					cout<<"Protocol: unknown\n";
					break;
			}

			/* define/compute tcp header offset
			tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
			size_tcp = TH_OFF(tcp)*4;
			if (size_tcp < 20) {
				printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
				return 0;
			} */
			
			
			print_payload(payload, size_payload); 
		}	
	
	}

	else{
		cout<<endl ;
		/* Get time stamp */
		count++ ;
		char *timeStamp = getTime(header) ;
		
		cout<<" " ;
		printf("%s",(ether_ntoa((const struct ether_addr *)&ethernet->ether_shost)));
		cout<<" -> " ;

		printf("%s",(ether_ntoa((const struct ether_addr *)&ethernet->ether_dhost))) ;

		cout<<" " ;
		printf("type 0x%.4x ",ntohs(ethernet->ether_type)) ;
		
		/* Get length of packet */

		cout<<"len "<<header->len<<endl ;

		

		/* print source and destination IP addresses with port */
		if(ip->ip_p==IPPROTO_TCP){
				/* print source and destination IP addresses with port */
				printf("%s:%d -> %s:%d ", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport), inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport)) ;
				
			}
			if(ip->ip_p==IPPROTO_UDP){
				/* print source and destination IP addresses with port */
				printf("%s:%d -> %s:%d ", inet_ntoa(ip->ip_src), ntohs(udp->uh_sport), inet_ntoa(ip->ip_dst), ntohs(udp->uh_dport));
			
		}

		/* determine protocol */
		switch(ip->ip_p) {
			case IPPROTO_TCP:
				cout<<"TCP\n";
				break;
			case IPPROTO_UDP:
				cout<<"UDP\n";
				break;
			case IPPROTO_ICMP:
				cout<<"ICMP\n";
				break;
			case IPPROTO_IP:
				cout<<"IP\n";
				break;
			default:
				cout<<"unknown\n";
				break;
		}
		print_payload(payload, size_payload);
		/*if (size_ip < 20) {
			printf("   * Invalid IP header length: %u bytes\n", size_ip);
			return 0;
		} */

		
		

		/* define/compute tcp header offset */
		/*tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
		size_tcp = TH_OFF(tcp)*4;
		if (size_tcp < 20) {
			printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
			return 0;
		} */

		
	
	}
return 0;
}

int main(int argc, char **argv)
{

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */
	char filter_exp[] = "";			/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = -1;			/* number of packets to capture */
	int lastOptInd = 0 ;
	print_app_banner();
	char option ;

	int flag_i, flag_r = 0 ;

		while((option = getopt(argc, argv, "irs")) != -1){
			switch (option){

				case 'i' :

					/* check for capture device name on command-line */
					if(flag_r==1){
						cout<<"r and i do not coexist"<<endl ;
						exit(1) ; ;
					}
					dev = argv[optind];
					
					if (dev == NULL){
						/* find a capture device if not specified on command-line */
						dev = pcap_lookupdev(errbuf);
						if (dev == NULL) {
							fprintf(stderr, "Couldn't find default device: %s\n",
				    					errbuf);
							exit(EXIT_FAILURE);
						}
					}
					flag_i = 1 ;
					break ;

				case 'r' :

					/* open file */
					if(flag_i == 1){
						cout<<"r and i do not coexist"<<endl ;
						exit(1) ;
					}
					handle = pcap_open_offline(argv[optind], errbuf);
					if (handle == NULL)
					{
						fprintf(stderr, "error reading pcap file: %s\n", errbuf);
						exit(1);
					}
					flag_r = 1 ;
					break ;

				case 's' :
					check_str = argv[optind] ;
										
					break ;

				default:

					cout<<"No option chosen"<<endl ;
					break ;
			}

			if(optind > lastOptInd){
				lastOptInd = optind ;
			}
		}
		
		if(argc > lastOptInd + 1){
			strcat(filter_exp, argv[lastOptInd + 1]);
			if(filter_exp == ""){
				cout<<"NULL filter"<<endl ;
			}
		}

	if (dev == NULL && flag_r == 0){
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
    					errbuf);
			exit(EXIT_FAILURE);
		}
	}

	/* get network number and mask associated with capture device */


	if((dev != NULL) && (flag_r == 0)){
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
			    dev, errbuf);
			net = 0;
			mask = 0;
		}
	}

	

	/* print capture info */
	/*printf("DEVICE: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp); */

	/* open capture device */

	if(dev!= NULL){
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
	}


	/* compile the filter expression */
	if (filter_exp != NULL){
		if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		cout<<filter_exp<<endl ;
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
		
	}
	/* now we can set our callback function */
	//pcap_handler *have_packet = (packe_handler *)(got_packet) ;
	pcap_loop(handle, num_packets, (pcap_handler)(got_packet), NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
	}





