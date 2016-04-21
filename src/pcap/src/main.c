#include "pcap.h"

int main(int argc, char **argv) {
    pcap_file_ctx *file = ld_pcap_file(argv[1]);
    close_pcap_file(file);
    return 0;
}
