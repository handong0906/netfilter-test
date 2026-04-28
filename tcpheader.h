#include <stdint.h>

#pragma pack(push, 1)
typedef struct _tcpheader
{
    uint16_t srcport;
    uint16_t dstport;
    uint32_t seqnum;
    uint32_t acknum;
    uint8_t offset_reserved;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgpointer;
        
}tcpheader;
#pragma pack(pop)