#include "pcap.h"
#include "memory.h"
#include "steg.h"
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
    char *option_data = NULL, *temp = NULL;
    FILE *fp = NULL;
    char *input_buffer = NULL;
    size_t input_buffer_size = 0;
    int exit_code = 1, a = 0;
    pcap_file_ctx *pcap = NULL;
    if ((option_data = get_option("input-file", argc, argv)) != NULL) {
        fp = fopen(option_data, "rb");
        if (fp == NULL) {
            printf("ERROR: Unable to open \"%s\".\n", option_data);
            return 1;
        }
        fseek(fp, 0L, SEEK_END);
        input_buffer_size = (size_t) ftell(fp);
        fseek(fp, 0L, SEEK_SET);
        input_buffer = (char *) getseg(input_buffer_size + 1);
        memset(input_buffer, 0, input_buffer_size);
        fread(input_buffer, 1, input_buffer_size, fp);
        fclose(fp);
    } else if ((option_data = get_option("input-buf", argc, argv)) != NULL) {
        input_buffer = option_data;
        input_buffer_size = strlen(input_buffer);
    }
    if (option_data == NULL) {
        printf("ERROR: The input buffer was not supplied. Use --input-buf=<data> or --input-file=<filepath> option.\n");
        return 1;
    }
    if ((option_data = get_option("pcap-file", argc, argv)) != NULL) {
        if ((pcap = ld_pcap_file(option_data)) == NULL) {
            printf("ERROR: Unable to open \"%s\".\n", option_data);
            goto ___hide_fini;
        }
    } else {
        printf("ERROR: The covering pcap file was not supplied. Use --pcap-file=<filepath> option.\n");
        goto ___hide_fini;
    }
    if ((option_data = get_option("pcap-out-file", argc, argv)) == NULL) {
        printf("ERROR: The output pcap file was not supplied. Use --pcap-out-file=<filepath> option.\n");
        goto ___hide_fini;
    }
    exit_code = (hide_buf(input_buffer, input_buffer_size, &pcap) == 0);
    if (exit_code == 0) {
        temp = pcap->path;
        pcap->path = option_data;
        exit_code = (save_pcap_file(pcap) == 0);
        if (exit_code != 0) {
            printf("ERROR: Unable to write to file \"%s\".\n", option_data);
        }
        pcap->path = temp;
    } else {
        printf("ERROR: Some error happened during the steganographic stage.\n");
    }
___hide_fini:
    option_data = input_buffer;
    for (a = 0; a < argc && option_data != NULL; a++) {
        if (option_data == argv[a] + strlen("--input-buf=")) {
            option_data = NULL;
        }
    }
    free(option_data);
    close_pcap_file(pcap);
    return exit_code;
}

int recover(const int argc, char **argv) {
    char *option_data = NULL;
    char *outbuf = NULL;
    size_t outbuf_size = 0;
    pcap_file_ctx *pcap = NULL;
    int exit_code = 1;
    FILE *fp = NULL;
    if ((option_data = get_option("pcap-file", argc, argv)) == NULL) {
        printf("ERROR: The pcap file was not supplied. Use the option --pcap-file=<filepath>.\n");
        return 1;
    }
    if ((pcap = ld_pcap_file(option_data)) == NULL) {
        printf("ERROR: Unable to open \"%s\".\n", option_data);
        return 1;
    }
    outbuf = recover_buf(pcap, &outbuf_size);
    exit_code = (outbuf == NULL);
    if (exit_code != 0) {
        printf("ERROR: Some error has happened during the recovering process.\n");
    } else {
        if ((option_data = get_option("output-file", argc, argv)) != NULL) {
            fp = fopen(option_data, "wb");
            if (fp == NULL) {
                printf("ERROR: Unable to create the file \"%s\".\n", option_data);
                exit_code = 1;
                goto ___recover_fini;
            }
        } else {
            fp = stdout;
        }
        fwrite(outbuf, 1, outbuf_size, fp);
        if (fp == stdout) {
            printf("\n");
        }
    }
___recover_fini:
    if (fp != stdout) {
        fclose(fp);
    }
    free(outbuf);
    close_pcap_file(pcap);
    return exit_code;
}

int help(const int argc, char **argv) {
    printf("use: %s --task=hide|recover [--input-buf=<data>|--input-file=<filepath> --pcap-file=<filepath> --pcap-out-file=<filepath>]\n", argv[0]);
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
