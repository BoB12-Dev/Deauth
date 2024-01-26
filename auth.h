

#pragma pack(push,1)
struct Radiotap {
    uint8_t it_version;
    uint8_t it_pad ;
    uint16_t it_len;
    uint32_t it_present;
    uint32_t padding[4];
}; // radiotap 11byte

struct Deauth_Frame {
    uint16_t type; //0x000c
    //uint16_t frameControl; //0xc000
    uint16_t duration; //0x003c
    uint8_t destination_address[6]; //FF:FF:FF:FF:FF:FF
    uint8_t source_address[6]; // AP mac
    uint8_t bssid[6];
    uint16_t fragment_num;
    uint16_t sequence_number; // == Fragment number
}; // beacon frame 24byte


struct Fixed_Parameter {
    uint8_t reason_code; // 0x0007 , 0x0003
}; // fixed 2byte


struct Packet {
    struct Radiotap radiotap;
    struct Deauth_Frame deauth;
    struct Fixed_Parameter fixed;
};
#pragma pack(pop)