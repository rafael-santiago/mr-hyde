#ifndef MOP_STEG_H
#define MOP_STEG_H 1

#include "types.h"
#include <stdlib.h>

int hide_buf(const char *input_buffer, size_t input_buffer_size, pcap_file_ctx **pcap_file);

char *recover_buf(pcap_file_ctx *pcap_file, size_t *output_size);

#endif

