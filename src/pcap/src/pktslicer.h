#ifndef PCAP_PKTSLICER_H
#define PCAP_PKTSLICER_H 1

#include <stdlib.h>

void set_pkt_field(const char *field, unsigned char *buf, size_t buf_size, const unsigned int value);

void *get_pkt_field(const char *field, const unsigned char *buf, size_t buf_size, size_t *field_size);

#endif
