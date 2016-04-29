/*
 *                                Copyright (C) 2016 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "chsum.h"
#include "endianess.h"
#include "pktslicer.h"

unsigned short ip_chsum(const unsigned char *data, const size_t dsize) {
    unsigned long sum = 0;
    const char unsigned *dp = data;
    const char unsigned *dp_end = dp + dsize;
    unsigned short next = 0;
    if (dp == NULL) {
        return 0;
    }
    while (dp < dp_end) {
        next = ((unsigned short) *dp) << 8;
        dp++;
        if (dp != dp_end) {
            next |= *dp;
        }
        sum += next;
        dp++;
    }
    while (sum >> 16) {
        sum = (sum >> 16) + (sum & 0xffff);
    }
    return (unsigned short)(~sum);
}

unsigned short tcp_chsum(const unsigned char *data, const size_t dsize, const unsigned char *src_ip, const size_t src_ip_size, const unsigned char *dst_ip, const size_t dst_ip_size, const unsigned short tcp_len) {
    int state = 0;
    const unsigned char *dp = NULL;
    const unsigned char *dp_end = NULL;
    unsigned long sum = 0x6;
    unsigned short next = 0, temp;
    if (data == NULL || src_ip == NULL || dst_ip == NULL) {
        return 0;
    }
    for (state = 0; state < 4; state++) {
        switch (state) {
            case 0:
                dp = data;
                dp_end = dp + dsize;
                break;

            case 1:
                dp = src_ip;
                dp_end = dp + src_ip_size;
                break;

            case 2:
                dp = dst_ip;
                dp_end = dp + dst_ip_size;
                break;

            case 3:
                temp = tcp_len;
                if (little_endian()) {
                    temp = htons(temp);
                }
                dp = (const unsigned char *)&temp;
                dp_end = dp + sizeof(temp);
                break;
        }
        while (dp < dp_end) {
            next = ((unsigned short) *dp) << 8;
            dp++;
            if (dp != dp_end) {
                next |= *dp;
            }
            sum += next;
            dp++;
        }
    }
    while (sum >> 16) {
        sum = (sum >> 16) + (sum & 0xffff);
    }
    return (unsigned short)(~sum);
}

void reval_tcp_ip_chsums(unsigned char *wire_buf, const size_t wire_buf_size) {
    const char *src_ip = NULL;
    const char *dst_ip = NULL;
    const char *ip_ihl = NULL;
    unsigned short chsum = 0;
    if (wire_buf == NULL) {
        return;
    }
    set_pkt_field("ip.chsum", wire_buf, wire_buf_size, 0);
    ip_ihl = get_pkt_field("ip.ihl", wire_buf, wire_buf_size, NULL);
    chsum = ip_chsum(wire_buf + 14, (unsigned short)(*ip_ihl * 4));
    if (little_endian()) {
        chsum = htons(chsum);
    }
    set_pkt_field("ip.chsum", wire_buf, wire_buf_size, chsum);
    set_pkt_field("tcp.chsum", wire_buf, wire_buf_size, 0);
    src_ip = get_pkt_field("ip.src", wire_buf, wire_buf_size, NULL);
    dst_ip = get_pkt_field("ip.dst", wire_buf, wire_buf_size, NULL);
    chsum = tcp_chsum(wire_buf + 14 + (*ip_ihl * 4),
                      wire_buf_size - 14 - (*ip_ihl * 4),
                      src_ip, 4, dst_ip, 4, wire_buf_size - 14 - (*ip_ihl * 4));
    if (little_endian()) {
        chsum = htons(chsum);
    }
    set_pkt_field("tcp.chsum", wire_buf, wire_buf_size, chsum);
}
