#pragma pack(push,1)
struct Radiotap {
    uint8_t it_version;
    uint8_t it_pad ;
    uint16_t it_len;
    uint32_t it_present;
    uint32_t padding[4];
}; // radiotap 24byte

struct Deauth_Frame {
    uint16_t type; //0x000c
    uint16_t duration; //0x003c
    uint8_t destination_address[6]; //FF:FF:FF:FF:FF:FF
    uint8_t source_address[6]; // AP mac
    uint8_t bssid[6];
    uint16_t fragment_num;
    uint16_t sequence_number;
}; // beacon frame 24byte


struct Fixed_Parameter {
    uint8_t reason_code; // 0x0007 , 0x0003
}; // fixed 2byte

struct Auth_Fixed_Parameter {
    uint16_t SEQ;
    uint16_t Algorithm;
    uint16_t Status_code;
};

struct Packet {
    struct Radiotap radiotap;
    struct Deauth_Frame deauth;
    struct Fixed_Parameter fixed;
};

struct Auth_Packet{
    struct Radiotap radiotap;
    struct Deauth_Frame auth;
    struct Auth_Fixed_Parameter Auth_Parameter;
};
#pragma pack(pop)