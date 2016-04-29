#include "steg.h"
#include "types.h"
#include "endianess.h"
#include "pktslicer.h"
#include "memory.h"
#include "chsum.h"
#include <stdio.h>
#include <string.h>

#define get_bit_from_byte(bb, b) ( ( ( (bb) >> (7 - b) ) & 1 ) )

static int has_enough_tcpip_packets(pcap_file_ctx *pcap_file, const size_t input_buffer_size) {
    unsigned char *proto = NULL;
    pcap_record_ctx *rp = NULL;
    int tcpip_nr = 0;
    int x = 0;
    for (rp = pcap_file->rec; rp != NULL; rp = rp->next) {
        proto = get_pkt_field("eth.type", rp->data, rp->hdr.incl_len, NULL);
        if (proto == NULL || memcmp(proto, "\x08\x00", 2) != 0) {
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
    unsigned char *data = NULL;
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
                if (little_endian()) {
                    input_buffer_size = htonl(input_buffer_size);
                }
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
            if (data == NULL || memcmp(data, "\x08\x00", 2) != 0) {
                rp = rp->next;
                continue;
            }
            data = get_pkt_field("ip.proto", rp->data, rp->hdr.incl_len, NULL);
            if (data == NULL || *data != 6) {
                rp = rp->next;
                continue;
            }
            data = get_pkt_field("tcp.reserv", rp->data, rp->hdr.incl_len, NULL);
            if (data == NULL) {
                rp = rp->next;
                continue;
            }
            bit = get_bit_from_byte(*ip, b);
            set_pkt_field("tcp.reserv", rp->data, rp->hdr.incl_len, (bit == 0) ? 0x80 : 0x82);
            reval_tcp_ip_chsums(rp->data, rp->hdr.incl_len);
            b = (b+1) % 8;
            if (b == 0) {
                ip++;
            }
            rp = rp->next;
        }
    }
    return 1;
}

char *recover_buf(pcap_file_ctx *pcap_file, size_t *output_size) {
    char *plaintext = NULL, *p = NULL, *p_end = NULL;
    pcap_record_ctx *rp = NULL;
    size_t b = 0;
    size_t plaintext_size = 0;
    unsigned char *data = NULL;
    if (pcap_file == NULL) {
        return NULL;
    }
    rp = pcap_file->rec;
    while (rp != NULL && b < (sizeof(plaintext_size) * 8)) {
        data = get_pkt_field("eth.type", rp->data, rp->hdr.incl_len, NULL);
        if (data == NULL || memcmp(data, "\x08\x00", 2) != 0) {
            rp = rp->next;
            continue;
        }
        data = get_pkt_field("ip.proto", rp->data, rp->hdr.incl_len, NULL);
        if (data == NULL || *data != 6) {
            rp = rp->next;
            continue;
        }
        data = get_pkt_field("tcp.reserv", rp->data, rp->hdr.incl_len, NULL);
        if (data == NULL) {
            rp = rp->next;
            continue;
        }
        plaintext_size = plaintext_size << 1 | ((*data) == 0x08 ? 1 : 0);
        b++;
        rp = rp->next;
    }
    b = 0;
    plaintext = (char *) getseg(plaintext_size + 1);
    memset(plaintext, 0, plaintext_size + 1);
    p = plaintext;
    p_end = p + plaintext_size;
    while (rp != NULL && p != p_end) {
        data = get_pkt_field("eth.type", rp->data, rp->hdr.incl_len, NULL);
        if (data == NULL || memcmp(data, "\x08\x00", 2) != 0) {
            rp = rp->next;
            continue;
        }
        data = get_pkt_field("ip.proto", rp->data, rp->hdr.incl_len, NULL);
        if (data == NULL || *data != 6) {
            rp = rp->next;
            continue;
        }
        data = get_pkt_field("tcp.reserv", rp->data, rp->hdr.incl_len, NULL);
        if (data == NULL) {
            rp = rp->next;
            continue;
        }
        *p = (*p) << 1 | ((*data) == 0x08 ? 1 : 0);
        b = (b + 1) % 8;
        if ((b % 8) == 0) {
            p++;
        }
        rp = rp->next;
    }
    if (output_size != NULL) {
        *output_size = plaintext_size;
    }
    return plaintext;
}
