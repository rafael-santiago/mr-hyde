#ifndef PCAP_PCAP_H
#define PCAP_PCAP_H 1

#include "types.h"

pcap_file_ctx *ld_pcap_file(const char *filepath);

void close_pcap_file(pcap_file_ctx *file);

#endif
