#include "pktslicer.h"
#include <string.h>

struct pkt_field_boundaries {
    const char *name;
    size_t start_off, end_off;
    unsigned int mask;
    unsigned int rsh;
};

// INFO(Santiago): This states the slicer behavior for each relevant packet field.
//                 The basic "gear" for this kind of "machine" is: ( ( ( pkt + start_off ) & mask ) >> lsh )
const struct pkt_field_boundaries g_pkt_fields[] = {
    { "eth.dst",     0,  5, 0xffffffff,  0 },
    { "eth.src",     6, 11, 0xffffffff,  0 },
    { "eth.type",   12, 13, 0xffffffff,  0 },
    { "ip.version", 14, 14, 0x000000f0,  4 },
    { "ip.ihl",     14, 14, 0x0000000f,  0 },
    { "ip.tos",     15, 15, 0xffffffff,  0 },
    { "ip.len",     16, 17, 0xffffffff,  0 },
    { "ip.id",      18, 19, 0xffffffff,  0 },
    { "ip.flags",   20, 20, 0x0000e000, 13 },
    { "ip.fragoff", 20, 21, 0x00001fff,  0 },
    { "ip.ttl",     22, 22, 0xffffffff,  0 },
    { "ip.proto",   23, 23, 0xffffffff,  0 },
    { "ip.chsum",   24, 25, 0xffffffff,  0 },
    { "ip.src",     26, 29, 0xffffffff,  0 },
    { "ip.dst",     30, 33, 0xffffffff,  0 },
    { "tcp.src",    34, 35, 0xffffffff,  0 },
    { "tcp.dst",    36, 37, 0xffffffff,  0 },
    { "tcp.seqno",  38, 41, 0xffffffff,  0 },
    { "tcp.ackno",  42, 45, 0xffffffff,  0 },
    { "tcp.len",    46, 46, 0x0000f000, 12 },
    { "tcp.reserv", 46, 47, 0x00000fc0,  4 },
    { "tcp.flags",  46, 47, 0x0000003f,  0 },
    { "tcp.window", 48, 49, 0xffffffff,  0 },
    { "tcp.chsum",  50, 51, 0xffffffff,  0 },
    { "tcp.urgp",   52, 53, 0xffffffff,  0 }
};

const size_t g_pkt_fields_size = sizeof(g_pkt_fields[0]) / sizeof(g_pkt_fields);

void set_pkt_field(const char *field, unsigned char *buf, size_t buf_size, const unsigned int value) {
    size_t p = 0;
    const unsigned char *buf_end = NULL;
    unsigned int *slice = NULL;
    if (field == NULL || buf == NULL) {
        return;
    }
    buf_end = buf + buf_size;
    for (p = 0; p < g_pkt_fields_size; p++) {
        if (strcmp(g_pkt_fields[p].name, field) == 0) {
            if (buf + g_pkt_fields[p].start_off + (g_pkt_fields[p].end_off - g_pkt_fields[p].start_off) > buf_end) {
                return;
            }
        }
        slice = ((unsigned int *)buf + g_pkt_fields[p].start_off);
        *slice |= value << g_pkt_fields[p].rsh;
    }
}

void *get_pkt_field(const char *field, const unsigned char *buf, size_t buf_size, size_t *field_size) {
    size_t p = 0;
    const unsigned char *buf_end = NULL;
    static unsigned int slice = 0;
    if (field == NULL || buf == NULL) {
        return NULL;
    }
    buf_end = buf + buf_size;
    for (p = 0; p < g_pkt_fields_size; p++) {
        if (strcmp(g_pkt_fields[p].name, field) == 0) {
            if (buf + g_pkt_fields[p].start_off + (g_pkt_fields[p].end_off - g_pkt_fields[p].start_off) > buf_end) {
                return NULL;
            }
            slice = *((unsigned int *)buf + g_pkt_fields[p].start_off);
            if (field_size != NULL) {
                *field_size = g_pkt_fields[p].end_off - g_pkt_fields[p].start_off;
            }
            slice = (slice & g_pkt_fields[p].mask) >> g_pkt_fields[p].rsh;
            return &slice;
        }
    }
    return NULL;
}
