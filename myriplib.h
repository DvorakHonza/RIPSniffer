#include <stdio.h>
#include <stdlib.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ether.h>

#define SIZE_ETHERNET 14
#define SIZE_RIP_HEADER 4 
#define SIZE_UDP_HEADER 8
#define SIZE_RIP_ENTRY 20
#define SIZE_IPV6_HEADER 40
#define RIPNG_PORT 521
#define RIP_MULT "ff02::9"

typedef unsigned int u_int;
typedef unsigned char u_char;
typedef unsigned short u_short;

/**
 *@brief rip_header structure represents header of RIP
 */
struct rip_header {
    u_char command; /**< Type of RIP message*/
    u_char version; /**< Version of RIP */
    u_short mbz;    /**< Reserved, must be zero*/ 
} RIP_HEADER;

/**
 *@brief rip_entry structure represents one RTE of RIPv1 or RIPv2
 */
struct rip_entry {
    u_short af_id;      /**< Address family identifier*/
    u_short route_tag;  /**< Route Tag*/
    u_int ip_addr;      /**< IPv4 address of advertised network*/
    u_int subnet_mask;  /**< Mask for network specified in ip_addr*/
    u_int next_hop;     /**< Next hop address for this network*/
    u_int metric;       /**< Metric of the route*/
}RIP_ENTRY;


/**
 * @brief Structure MD5_entry is used when recieved RIPv2 packet is authenticated with MD5
 */
struct MD5_entry {
    u_short af_id;          /**< Address family identifier, muset be 0xffff*/
    u_short auType;         /**< Autheticaton type, 3 for Keyed Message Digest*/      
    u_short offset;         /**< Length of RIPv2 packet*/
    u_char KeyID;           /**< Key identifier*/
    u_char auth_data_len;   /**< Length of autentication data trailer*/
    u_int seq_num;          /**< Sequence number*/
    u_int mbz1;             /**< Reserverd, must be zero*/
    u_int mbz2;             /**< Reserverd, must be zero*/
} MD5_ENTRY;

/**
 * @brief Represents header of IPv6
 */
struct ipv6_header {
    u_char tr_class;    /**< Traffic class*/
    u_int version:4;    /**< Version of internet protocol*/
    u_int label:20;     /**< Flow Label*/
    u_short len;        /**< Payload length*/
    u_char nxt_hdr;     /**< Protocol used inside of IP*/
    u_char hop_limit;   /**< Hop limit*/
    u_char src[16];     /**< Source IPv6 address*/
    u_char dest[16];    /**< Destination IPv6 address*/
} IPV6_HEADER;


/**
 * @brief Represents RTE of RIPng
 */
struct ripng_entry {
    u_char prefix[16];  /**< Network prefix*/
    u_short tag;        /**< Route tag*/
    u_char pref_len;    /**< Prefix length*/
    u_char metric;      /**< Route metric*/
} RIPNG_ENTRY;


/**
 * @brief Represents structure of RIPng packet with next hop RTE and one normal RTE
 */
struct ripng {
    struct rip_header hdr;          /**< RIPng header*/
    struct ripng_entry next_hop;    /**< Next hop RTE*/
    struct ripng_entry entry;       /**< Advertised network RTE*/
} RIPNG;

struct ripng_req {
    struct rip_header hdr;
    struct ripng_entry entry;
};

/**
 * @brief Prints IPv4 address in hexadecimal form
 * 
 * @param addr String representation of IPv4 address
 * 
 */
void print_ip_hex(char *addr);

/**
 * @brief Prints one RIPv1 RTE
 * 
 * @param entry Pointer to structure containing RTE information
 * 
 */
void print_entryv1(struct rip_entry *entry);

/**
 * @brief Prints one RIPv2 RTE
 * 
 * @param entry Pointer to structure containing RTE information
 * 
 */
void print_entry(struct rip_entry *entry);

/**
 * @brief Prints one RIPng RTE
 * 
 * @param entry Pointer to structure containing RTE information
 * @param nxthop String representation of IPv6 address that is next hop address for entry
 */
void print_entry6(struct ripng_entry *entry, char *nxthop);

/**
 * @brief Prints authentication RTE
 * 
 * @param entry Pointer to structure containing RTE information
 * 
 * @return 2 if authentication is simple password, 3 if Keyed Message Digest, -1 otherwise
 */
int print_auth(struct rip_entry *entry);

/**
 * @brief Prints RIP header
 * 
 * @param hdr Pointer to structure containing header information
 */
void print_rip_header(struct rip_header* hdr);

/**
 * @brief Checks if string is valid IPv6 address
 * 
 * @param ip String format of IPv6 address
 * 
 * @return 1 if address is valid, 0 otherwise
 */
int valid_ip6(char *ip);

/**
 * @brief Prints Ethernet header, IPv4 header and UDP header
 * 
 * @param iph Pointer to structure containing IP information
 * @param udph Pointer to structure containing UDP information
 * @param ethh Pointer to structure containing Ethernet information
 */
void print_header4(struct ip *iph, struct udphdr *udph, struct ether_header *ethh);

/**
 * @brief Prints Ethernet header, IPv6 header and UDP header
 * @param iph Pointer to structure containing IP information
 * @param udph Pointer to structure containing UDP information
 * @param ethh Pointer to structure containing Ethernet information
 */
void print_header6(struct ipv6_header *ip6h, struct udphdr *udph, struct ether_header *ethh);

/**
 * @brief Creates RIPng response packet with specified information
 * 
 * @param packet Pointer to ripng structure, where the packet will be stored
 * @param nexthop Next hop prefix
 * @param entry_addr Advertised network prefix
 * @param tag Route tag
 * @param prefix_len Prefix length of entry_addr
 * @param metric Metric
 */
void craft_attacking_packet(struct ripng *packet, char *nexthop, char *entry_addr,
                            u_short tag, u_char prefix_len, u_char metric);

/**
 * @brief Creates RIPng request packet with specified information
 * 
 * @param packet Pointer to structure representing RIPng request packet
 * @param entry_addr String representation of IPv6 address of requested network
 * @param prefix_len Prefix length of address entry_addr
 */
void craft_request_packet(struct ripng_req *packet, char *entry_addr, u_char prefix_len);

/**
 * @brief Checks whether IPv6 address addr is link-local 
 * 
 * @param addr IPv6 address in string format
 * 
 * @return Returns 1 if addr is link-local, 0 otherwise
 */
int is_linklocal(char *addr);