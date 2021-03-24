#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>

#include "myriplib.h"


int main(int argc, char *argv[]) {

    int opt;
    int ifnd = 0, afnd = 0, rfnd = 0;
    char *interface;
    char *des_net;
    int pref_len, if_index;
    int hops = 255;

    while ((opt = getopt(argc, argv, ":hi:ar:")) != -1) {
        switch (opt) {
            case 'h':
                printf("Usage:\n\tsudo ./myriprequest -i <interface> [-a|-r <IPv6/[16-128]]\n");
                printf("Parameters -a and -r are mutually exclusive.");
                exit(-1);

            case 'i':
                ifnd = 1;
                interface = optarg;
                if_index = if_nametoindex(interface);
                break;
            
            case 'a':
                afnd = 1;
                des_net = "::";
                pref_len = 0;
                break;

            case 'r':
                rfnd = 1;
                char *token;
                token = strtok(optarg, "/");
                des_net = token;

                if (!valid_ip6(des_net)) {
                    fprintf(stderr, "Invalid network address, expecting format <IPv6>/prefix_len.\n");
                    exit(-1);
                }
                if ((token = strtok(NULL, "/")) == NULL) {
                    fprintf(stderr, "Invalid network address, expecting format <IPv6>/prefix_len.\n");
                    exit(-1);
                }
                pref_len = strtol(token, NULL, 10);
                if (pref_len > 128 || pref_len < 16) {
                    fprintf(stderr, "Prefix length must be between 16 and 128 inclusive.\n");
                    exit(-1);
                }
                break;

            case ':':
                fprintf(stderr, "Argument -%c is missing value.\n", optopt);
                exit(-1);
                break;

            default:
                fprintf(stderr, "Unknown paramater entered.\n");
                exit(-1);
        }   
    }
    if (!ifnd) {
        fprintf(stderr, "Outgoing interface must be specified.\n");
        exit(-1);
    }

    if (!(afnd || rfnd)) {
        fprintf(stderr, "Either -a or -r parameter must be specified\n");
        exit(-1);
    }

    if (afnd && rfnd) {
        fprintf(stderr, "Parameters -a and -r cannot be used simultaneously.\n");
        exit(-1);
    }

    struct sockaddr_in6 local, dest;
    struct ripng_req req;
    int sock;

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

    craft_request_packet(&req, des_net, pref_len);

    /*
        Send attacking packet to it's destination
    */
    if (sendto(sock, (const void *)&req, sizeof(req), 0, (const struct sockaddr *)&dest, INET6_ADDRSTRLEN) <= 0) {
        perror("sendto() failed");
        exit(-1);
    }

    if (afnd) {
        printf("Request for whole routing table has been sent.\n");
    } else {
        printf("Request for address %s/%d has been sent.\n", des_net, pref_len);
    }

    return 0;
}