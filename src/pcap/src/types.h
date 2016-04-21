#ifndef PCAP_TYPES_H
#define PCAP_TYPES_H 1

typedef struct _pcap_global_header_t {
    unsigned int magic_number;
    unsigned short version_major;
    unsigned short version_minor;
    int thiszone;
    unsigned int sigfigs;
    unsigned int snaplen;
    unsigned int network;
}pcap_global_header_t;

typedef struct _pcap_record_header_t {
    unsigned int ts_sec;
    unsigned int ts_usec;
    unsigned int incl_len;
    unsigned int orig_len;
}pcap_record_header_t;

typedef struct _pcap_record_ctx {
    pcap_record_header_t hdr;
    unsigned char *data;
    struct _pcap_record_ctx *next;
}pcap_record_ctx;

typedef struct _pcap_file_ctx {
    pcap_global_header_t hdr;
    pcap_record_ctx *rec;
    char *path;
}pcap_file_ctx;

#endif
