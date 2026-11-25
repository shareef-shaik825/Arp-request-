/* arp_common.h */
#ifndef ARP_COMMON_H
#define ARP_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#define ARP_REQUEST 1
#define ARP_REPLY 2

/* ARP packet layout (28 bytes, for Ethernet + IPv4) */
struct arp_pkt {
    unsigned short htype;  /* hardware type: 1 = Ethernet */
    unsigned short ptype;  /* protocol type: 0x0800 = IPv4 */
    unsigned char hlen;    /* 6 */
    unsigned char plen;    /* 4 */
    unsigned short oper;   /* 1 = request, 2 = reply */
    unsigned char sha[6];  /* sender MAC */
    unsigned char spa[4];  /* sender IP */
    unsigned char tha[6];  /* target MAC */
    unsigned char tpa[4];  /* target IP */
} __attribute__((packed));

/* Ethernet header + ARP payload */
struct eth_arp_frame {
    unsigned char dst[6];
    unsigned char src[6];
    unsigned short type;  /* 0x0806 = ARP */
    struct arp_pkt arp;
} __attribute__((packed));

/* Get this interface's MAC and index */
static int get_if_info(int sock, const char *ifname,
                       unsigned char mac[6], int *ifindex)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) { perror("SIOCGIFHWADDR"); return -1; }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) { perror("SIOCGIFINDEX"); return -1; }
    *ifindex = ifr.ifr_ifindex;
    return 0;
}

static void print_mac(const unsigned char *m)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

#endif
