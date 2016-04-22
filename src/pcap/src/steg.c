#include "steg.h"
#include "types.h"
#include "pktslicer.h"
#include <stdio.h>

#define get_bit_from_byte(bb, b) ( ( ( (bb) >> (7 - b) ) & 1 ) )

static int has_enough_tcpip_packets(pcap_file_ctx *pcap_file, const size_t input_buffer_size) {
    unsigned int *proto = NULL;
    pcap_record_ctx *rp = NULL;
    int tcpip_nr = 0;
    for (rp = pcap_file->rec; rp != NULL; rp = rp->next) {
        proto = get_pkt_field("eth.type", rp->data, rp->hdr.incl_len, NULL);
        if (proto == NULL || *proto != 0x0800) {
            continue;
        }
        proto = get_pkt_field("ip.proto", rp->data, rp->hdr.incl_len, NULL);
        if (proto == NULL || *proto != 6) {
            continue;
        }
        tcpip_nr++;
    }
    return (((input_buffer_size * 8) + sizeof(input_buffer_size) * 8) <= tcpip_nr);
}

int hide_buf(const char *input_buffer, size_t input_buffer_size, pcap_file_ctx **pcap_file) {
    pcap_file_ctx *p = NULL;
    pcap_record_ctx *rp = NULL;
    unsigned int *data = NULL;
    unsigned char bit = 0;
    const char *ip = NULL, *ip_end = NULL;
    int state = 0;
    int b = 0;
    if (input_buffer == NULL || pcap_file == NULL) {
        return 0;
    }
    p = *pcap_file;
    if (!has_enough_tcpip_packets(p, input_buffer_size)) {
        printf("ERROR: the amount of tcp/ip packets in pcap file is not enough to perform the steganography. It needs at least %d tcp/ip packets.\n", (input_buffer_size * 8) + (sizeof(input_buffer_size) * 8));
        return 0;
    }
    rp = p->rec;
    for (state = 0; state < 2; state++) {
        switch (state) {

            case 0:
                ip = (unsigned char *)&input_buffer_size;
                ip_end = ip + sizeof(input_buffer_size);
                break;

            case 1:
                ip = input_buffer;
                ip_end = ip + input_buffer_size;
                break;

        }
        while (rp != NULL && ip != ip_end) {
            data = get_pkt_field("eth.type", rp->data, rp->hdr.incl_len, NULL);
            if (data == NULL || *data != 0x0800) {
                continue;
            }
            data = get_pkt_field("ip.proto", rp->data, rp->hdr.incl_len, NULL);
            if (data == NULL || *data != 6) {
                continue;
            }
            data = get_pkt_field("tcp.reserv", rp->data, rp->hdr.incl_len, NULL);
            if (data == NULL) {
                continue;
            }
            bit = get_bit_from_byte(*ip, b);
            set_pkt_field("tcp.reserv", rp->data, rp->hdr.incl_len, (*data) & ((~1) | bit));
            // TODO(Santiago): refresh tcp and ip checksum.
            b = (b+1) % 8;
            if (b == 0) {
                ip++;
            }
            rp = rp->next;
        }
    }
    return 1;
}

char *recover_buf(pcap_file_ctx *pcap_file, size_t *ouput_size) {
    return NULL;
}
