#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include "myriplib.h"

void print_ip_hex(char *addr) {

    char *tmp;
    int tmp_int;
    
    tmp = strtok(addr, ".");
    while (tmp != NULL) {
        tmp_int = strtol(tmp, NULL, 10);
        printf("%x ", tmp_int);
        tmp = strtok(NULL, ".");
    }
    printf("\n");
}

void print_rip_header(struct rip_header *hdr) {
    printf("Routing information protocol\n");
        if (hdr->command == 1) {
            printf("\tCommand: Request\n");
        } else if (hdr->command == 2) {
            printf("\tCommand: Response\n");
        } else {
            printf("\tCommand: unknown\n");
        }
}

void print_entry(struct rip_entry *entry) {

    struct in_addr tmp;
    tmp.s_addr = entry->ip_addr;
    printf("\t\tIP Address: %s\n", inet_ntoa(tmp));
    tmp.s_addr = entry->subnet_mask;
    printf("\t\tSubnet mask: %s\n", inet_ntoa(tmp));
    tmp.s_addr = entry->next_hop;
    printf("\t\tNext hop: %s\n", inet_ntoa(tmp));
    printf("\t\tMetric: %d\n", ntohl(entry->metric));

}

void print_entryv1(struct rip_entry *entry) {
    struct in_addr tmp;
    tmp.s_addr = entry->ip_addr;
    printf("\t\tIP Address: %s\n", inet_ntoa(tmp));
    printf("\t\tMetric: %d\n", ntohl(entry->metric));
}

int print_auth(struct rip_entry *entry) {
    printf("\tAuthentication: ");
    if (ntohs(entry->route_tag) == 2) {
        printf("Simple Password\n");
        u_int *passwd;
        passwd = (&(entry->ip_addr));
        printf("\t\tPassword: %s\n", (char *)passwd);
        return 2;

    } else if (ntohs(entry->route_tag) == 3) {
        struct MD5_entry *md5 = (struct MD5_entry *)(entry);
        printf("Keyed Message Digest\n");
        printf("\t\tDigest offset: %d\n", ntohs(md5->offset));
        printf("\t\tKey ID: %d\n", md5->KeyID);
        printf("\t\tAuthentication data length: %d\n", md5->auth_data_len);
        printf("\t\tSequence number: %d\n", ntohl(md5->seq_num));

        u_int *data = (u_int *)entry;
        data += (ntohs(md5->offset) / 4);

        printf("\t\tAuthentication Data Trailer:\n\t\t\t");
        for (int i = 0; i < 4; i++) {
            printf("%08x", ntohl(data[i]));
        }
        printf("\n");
        return 3;
    } else {
        return -1;
    }
}

void print_entry6(struct ripng_entry *entry, char *nxthop) {

    char prefix[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, entry->prefix, prefix, INET6_ADDRSTRLEN);
    printf("\t\tPrefix: %s/%d\n", prefix, entry->pref_len);
    if (strcmp(nxthop, "") != 0) {
        printf("\t\tNext hop: %s\n", nxthop);
    }
    printf("\t\tRoute tag: 0x%04x\n", entry->tag);
    printf("\t\tMetric: %d\n", entry->metric);
}

int valid_ip6(char *ip) {
    char dest[INET6_ADDRSTRLEN];
    if (inet_pton(AF_INET6, ip, dest) == 0) {
        return 0;
    } else {
        return 1;
    }
}

void print_header6(struct ipv6_header *ip6h, struct udphdr *udph, struct ether_header *ethh) {

    char src[INET6_ADDRSTRLEN];
    char dst[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, ip6h->src, src, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, ip6h->dest, dst, INET6_ADDRSTRLEN);

    printf("Ethernet\n");
    printf("\tSrc MAC: %s\t\t", ether_ntoa((const struct ether_addr *)&ethh->ether_shost));
    printf("Dest MAC: %s\n", ether_ntoa((const struct ether_addr *)&ethh->ether_dhost));
    printf("Internet Protocol version 6\n");
    printf("\tSrc IP: %s\t", src);
    printf("Dest IP: %s\n", dst);
    printf("User Datagram Protocol\n");
    printf("\tSrc port: %d\t\t\t\tDest port: %d\n", ntohs(udph->uh_sport), ntohs(udph->uh_dport));
}

void print_header4(struct ip *iph, struct udphdr *udph, struct ether_header *ethh) {

    printf("Ethernet\n");
    printf("\tSrc MAC: %s\t", ether_ntoa((const struct ether_addr *)&ethh->ether_shost));
    printf("Dest MAC: %s\n", ether_ntoa((const struct ether_addr *)&ethh->ether_dhost));
    printf("Internet Protocol version 4\n");
    printf("\tSrc IP: %s\t\tDest IP: %s\n", inet_ntoa(iph->ip_src), inet_ntoa(iph->ip_dst));
    printf("User Datagram Protocol\n");
    printf("\tSrc port: %d\t\t\tDest port: %d\n", ntohs(udph->uh_sport), ntohs(udph->uh_dport));
}

void craft_attacking_packet(struct ripng *packet, char *nexthop, char *entry_addr,
                            u_short tag, u_char prefix_len, u_char metric) {
    packet->hdr.command = 2;
    packet->hdr.version = 1;
    packet->hdr.mbz = 0;

    inet_pton(AF_INET6, nexthop, packet->next_hop.prefix);
    packet->next_hop.tag = 0;
    packet->next_hop.pref_len = 0;
    packet->next_hop.metric = 0xff;

    inet_pton(AF_INET6, entry_addr, packet->entry.prefix);
    packet->entry.tag = htons(tag);
    packet->entry.pref_len = prefix_len;
    packet->entry.metric = metric;
}

void craft_request_packet(struct ripng_req *packet, char *entry_addr, u_char prefix_len) {
    packet->hdr.command = 1;
    packet->hdr.version = 1;
    packet->hdr.mbz = 0;


    inet_pton(AF_INET6, entry_addr, packet->entry.prefix);
    packet->entry.tag = 0x0000;
    packet->entry.pref_len = prefix_len;
    packet->entry.metric = 16;
}

int is_linklocal(char *addr) {

    char mask[INET6_ADDRSTRLEN];
    char bin_addr[INET6_ADDRSTRLEN];
    char prefix[INET6_ADDRSTRLEN];
    char and[16];
    inet_pton(AF_INET6, "ffc0::", mask);
    inet_pton(AF_INET6, "fe80::", prefix);
    inet_pton(AF_INET6, addr, bin_addr);

    for (int i = 0; i < 16; i++) {
        and[i] = mask[i] & bin_addr[i];
    }

    if (strcmp(and, prefix) == 0) {
        return 1;
    } else {
        return 0;
    }
}