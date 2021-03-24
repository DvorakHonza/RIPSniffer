#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>
#include "myriplib.h"

int packet_num = 0;

void mypcap_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    
    (void)args;

    struct ip *iph;
    struct udphdr *udph;
    u_int ip_size;
    struct rip_header *riph;
    struct rip_entry *entry;
    struct ether_header *ethh;
    u_int number_of_entries;
    struct ipv6_header *ip6h;
    struct ripng_entry *ngentry;

    /*
        Packet information with border separating each packet
    */
    packet_num++;
    printf("------------------------------------------------------------------------------------\n");
    printf("                                   Packet no. %d\n", packet_num);
    printf("                             %s", ctime((const time_t *)&header->ts.tv_sec));
    printf("------------------------------------------------------------------------------------\n");

    /*
        Set pointer to Ethernet header
    */
    ethh = (struct ether_header *)packet; 

    /*
        Set pointer to IP header
    */
    iph = (struct ip*)(packet + SIZE_ETHERNET);

    /*
        Set pointer to UDP header
    */
    if (iph->ip_v == 4) {
        ip_size = iph->ip_hl * 4;
    } else {
        ip6h = (struct ipv6_header *)(packet + SIZE_ETHERNET);
        ip_size = SIZE_IPV6_HEADER;
    }

    udph = (struct udphdr *)(packet + SIZE_ETHERNET + ip_size);

    /*
        Set pointer to RIP header
    */
    riph = (struct rip_header *)(packet + SIZE_ETHERNET + ip_size + SIZE_UDP_HEADER);

    /*
        Determine which RIP version you are dealing with
    */
    if (iph->ip_v == 4) {

        /*
            Print Ethernet, IPv4 and UDP headers, it is same for RIPv1 and RIPv2
        */
        entry = (struct rip_entry *)(packet + SIZE_ETHERNET + ip_size + SIZE_UDP_HEADER + SIZE_RIP_HEADER);
        print_header4(iph, udph, ethh);
        print_rip_header(riph);

        /*
            Calculate number of RTEs in the packet
        */
        number_of_entries = ((ntohs(udph->uh_ulen) - SIZE_UDP_HEADER - SIZE_RIP_HEADER) / SIZE_RIP_ENTRY);

        /*
            Process RIPv1 packet:
                Print entry and move on to next one
        */
        if (riph->version == 1) {
            printf("\tVersion: RIPv1\n");
            for (u_int i = 1; i <= number_of_entries; i++) {
                printf("\tEntry %d:\n", i);
                print_entryv1(entry);
                entry = (entry + 1);
            }
        /*
            Process RIPv2 packet:
                Check if the first entry contains authentication (af_id == 0xffff)
                if so check which one and print proper information then print remaining RTEs in packet
        */
        } else {
            printf("\tVersion: RIPv2\n");
            if (entry->af_id == 0xffff) {
                if (print_auth(entry) == 3) {
                    number_of_entries--;
                }
                entry = (entry + 1);
            }
            if (number_of_entries == 1) {
                print_entry(entry);
            } else {
                for (u_int i = 1; i < number_of_entries; i++) {
                    printf("\tEntry %d:\n", i);
                    print_entry(entry);
                    entry = (entry + 1);
                }    
            }
        }
    } else {
        
        /*
            Print Ethernet, IPv6 and UDP headers 
        */
        ngentry = (struct ripng_entry *)(packet + SIZE_ETHERNET + SIZE_IPV6_HEADER + SIZE_UDP_HEADER + SIZE_RIP_HEADER);

        print_header6(ip6h, udph, ethh);
        print_rip_header(riph);

        /*
            Calculate number of RTEs inside RIPng packet
        */
        number_of_entries = ((ntohs(udph->uh_ulen) - SIZE_UDP_HEADER - SIZE_RIP_HEADER) / SIZE_RIP_ENTRY);

        /*
            Process RIPng packet:
                Check if the RTE is next hop RTE (metric == 0xff) if so update nxthop variable
                Proceed to print RIPng RTEs with next hop included
        */
        char nxthop[INET6_ADDRSTRLEN] = "";
        printf("\tVersion: RIPng\n");
        for (u_int i = 1; i <= number_of_entries; i++) {
            if (ngentry->metric == 0xff) {
                inet_ntop(AF_INET6, ngentry->prefix, nxthop, INET6_ADDRSTRLEN);
                number_of_entries--;
                i--;
            } else {
                printf("\tEntry %d:\n", i);
                print_entry6(ngentry, nxthop);
            }
            ngentry += 1;
        }
    }
    printf("\n"); 
}


int main (int argc, char *argv[]) {

    int opt;
    char *interface = NULL;
    int ifnd = 0;

    /*
        Checking command line paramaters
    */

    if (argc == 1) {
        fprintf(stderr, "Specifying interface is required. Try -h.\n");
        exit(2);
    } else {
        while ((opt = getopt(argc, argv, ":i:h")) != -1) {
            switch (opt) {
                case 'h':
                    printf("Usage:\n\tsudo ./myripsniffer -i <interface>\n\n");
                    exit(2);

                case 'i':
                    interface = optarg;
                    ifnd = 1;
                    break;

                case ':':
                    fprintf(stderr, "Missing interface name.\n");
                    exit(-1);

                default:
                    fprintf(stderr, "Invalid arguments have been entered.\n");
                    exit(-1);
            }
        }
    }

    if (!ifnd) {
        fprintf(stderr, "Parameter -i <interface> not found, try ./myripsniffer -h\n");
        exit(-1);
    }


    pcap_t *handle;
    char errbuff[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netaddr;
    bpf_u_int32 mask;
    struct bpf_program filter;

    /*
        Set up specified interface to start sniffing
    */
    if (pcap_lookupnet(interface, &netaddr, &mask, errbuff) == -1) {
        fprintf(stderr, "pcap_lookupnet() failed: %s\n", errbuff);
        exit(-1);
    }

    /*
        Open session for sniffing
    */
    if ((handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuff)) == NULL) {
        fprintf(stderr, "pcap_open_live() failed: %s\n", errbuff);
        exit(-1);
    }

    /*
        Compile filter to sniff only RIP and RIPng packets
    */
    if (pcap_compile(handle, &filter, "udp portrange 520-521", 0, netaddr) == -1) {
        perror("pcap_compile() failed");
        exit(-1);
    }

    /*
        Set up the filter
    */
    if (pcap_setfilter(handle, &filter) == -1) {
        perror("pcap_setfilter() failed");
        exit(-1);
    }

    /*
        Capturing packets in loop and processing them with mypcap_handler function
    */
    if (pcap_loop(handle, -1, mypcap_handler, NULL) == -1) {
        perror("pcap_loop() failed");
    }

    /*
        Close sniffing session
    */
    pcap_close(handle);

    return 1;
}