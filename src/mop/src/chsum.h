#ifndef MOP_CHSUM_H
#define MOP_CHSUM_H 1

#include <stdlib.h>

unsigned short ip_chsum(const unsigned char *data, const size_t dsize);

unsigned short tcp_chsum(const unsigned char *data, const size_t dsize, const unsigned char *src_ip, const size_t src_ip_size, const unsigned char *dst_ip, const size_t dst_ip_size, const unsigned short tcp_len);

void reval_tcp_ip_chsums(unsigned char *wire_buf, const size_t wire_buf_size);

#endif
