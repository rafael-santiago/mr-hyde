#include "pcap.h"
#include <string.h>
#include <stdio.h>

char *get_option(const char *option, const int argc, char **argv) {
    int a;
    char temp[255] = "";
    if (option == NULL) {
        return NULL;
    }
    strncpy(temp, "--", sizeof(temp) - 1);
    strncat(temp, option, sizeof(temp) - 1);
    strncat(temp, "=", sizeof(temp) - 1);
    for (a = 0; a < argc; a++) {
        if (strstr(argv[a], temp) == argv[a]) {
            return (argv[a] + strlen(temp));
        }
    }
    return NULL;
}

char *get_boolean_option(const char *option, const int argc, char **argv) {
    int a;
    char temp[255] = "";
    if (option == NULL) {
        return NULL;
    }
    strncpy(temp, "--", sizeof(temp) - 1);
    strncat(temp, option, sizeof(temp) - 1);
    for (a = 0; a < argc; a++) {
        if (strcmp(argv[a], temp) == 0) {
            return (argv[a] + strlen(temp));
        }
    }
    return NULL;
}

int hide(const int argc, char **argv) {
    return 1;
}

int recover(const int argc, char **argv) {
    return 1;
}

int help(const int argc, char **argv) {
    printf("use: %s --task=hide|recover [--input-buf=<data>|--input-file=<filepath> --pcap-file=<filepath>]\n", argv[0]);
    return 0;
}

int main(int argc, char **argv) {
//    pcap_file_ctx *file = ld_pcap_file(get_option("pcap-file", argc, argv));
//    close_pcap_file(file);
//    printf("%s\n", get_option("pcap-file", argc, argv));
    char *task = NULL;
    if (get_boolean_option("help", argc, argv) != NULL) {
        return help(argc, argv);
    }
    task = get_option("task", argc, argv);
    if (task != NULL && strcmp(task, "hide") == 0) {
        return hide(argc, argv);
    } else if (task != NULL && strcmp(task, "recover") == 0) {
        return recover(argc, argv);
    }
    return help(argc, argv);
}
