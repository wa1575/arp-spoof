#ifndef UTILL_H
#define UTILL_H

#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <net/if.h> //ifr 사용
#include <netinet/in.h>
#include <sys/ioctl.h>

#pragma pack(push, 1)

struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};

struct EthIpPacket {
    EthHdr eth_;
    IpHdr ip_;
};

struct session{
    Ip sender_ip;
    Mac sender_mac;

    Ip target_ip;
    Mac target_mac;
};

#pragma pack(pop)


extern int get_mMAC(const char *ifname, u_char* myMAC);
extern int get_mIP(const char *dev, u_char* myIP);
extern int is_attack( EthArpPacket * pkt, session * session);
extern void make_packet(EthArpPacket * packet, Mac targetM, Mac srcM, int op, Ip senderIP, Ip targetIP);
extern void find_mac(pcap_t* handle, struct pcap_pkthdr *rep_header, int session_num, const u_char * rep_packet, uint8_t * attacker_mac, Ip attacker_ip, session * sessions);


class utill
{
public:
    utill();
};

#endif // UTILL_H
