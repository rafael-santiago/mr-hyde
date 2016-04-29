/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_LINE_SIZE     0xffff

#define USAGE_TIP "usage: %s --task=hide|recover [--input-file=<filepath>|--input-buf=<data> --output-file=<filepath> "\
                  "--cover-file=<filepath>]\n"

static char *get_next_line_from_file(FILE *fp);

static char get_blank_from_bit(const char bit);

static char get_bit_from_blank(const char blank);

static int get_lines_total_from_file(FILE *fp);

static long get_bytes_total_from_file(FILE *fp);

static int has_enough_lines(size_t input_bytes, FILE *cover_fp);

static int hide_byte(const unsigned char byte, FILE *cover_fp, FILE *output_fp);

static int hide(const char *input_buf, const size_t input_buf_size, const char *cover_path, const char *output_path);

static unsigned char recover_byte(FILE *input_fp);

static int recover(FILE *input_fp, FILE *output_fp);

static char *get_option(const char *option, char **argv, int argc);

static char *get_next_line_from_file(FILE *fp) {
    char *line = NULL;
    size_t l = 0;
    char c = 0;
    if (fp == NULL || feof(fp)) {
        return NULL;
    }
    line = (char *) malloc(MAX_LINE_SIZE);
    memset(line, 0, MAX_LINE_SIZE);
    c = fgetc(fp);
    l = 0;
    while (!feof(fp) && c != '\n' && c != '\r') {
        line[l] = c;
        c = fgetc(fp);
        l = (l + 1) % MAX_LINE_SIZE;
    }
    return line;
}

static char get_blank_from_bit(const char bit) {
    return (bit == 0) ? ' ' : '\t';
}

static char get_bit_from_blank(const char blank) {
    return (blank == ' ') ? 0 : 1;
}

static int get_lines_total_from_file(FILE *fp) {
    int t = 0;
    char *line = NULL;
    if (fp == NULL) {
        return 0;
    }
    fseek(fp, 0L, SEEK_SET);
    line = get_next_line_from_file(fp);
    while (line != NULL) {
        t++;
        line = get_next_line_from_file(fp);
        free(line);
    }
    fseek(fp, 0L, SEEK_SET);
    return t;
}

static long get_bytes_total_from_file(FILE *fp) {
    long t = 0;
    if (fp == NULL) {
        return 0;
    }
    fseek(fp, 0L, SEEK_END);
    t = ftell(fp);
    fseek(fp, 0L, SEEK_SET);
    return t;
}

static int has_enough_lines(size_t input_bytes, FILE *cover_fp) {
    int cover_lines_total = get_lines_total_from_file(cover_fp);
    return  ((input_bytes * 8 + (sizeof(long) * 8)) <= cover_lines_total);
}

static int hide_byte(const unsigned char byte, FILE *cover_fp, FILE *output_fp) {
    int b;
    char *line = NULL;
    for (b = 0; b < 8; b++) {
        line = get_next_line_from_file(cover_fp);
        if (line == NULL) {
            return 0;
        }
        fprintf(output_fp, "%s%c\n", line, get_blank_from_bit((byte >> (7 - b)) & 0x1));
        free(line);
    }
    return 1;
}

static int hide(const char *input_buf, const size_t input_buf_size, const char *cover_path, const char *output_path) {
    const char *ip = input_buf;
    const char *ip_end = ip + input_buf_size;
    FILE *cover_fp = NULL;
    FILE *output_fp = NULL;
    unsigned char byte = 0;
    int b = 0;
    int should_continue = 1;
    if (input_buf == NULL || cover_path == NULL || output_path == NULL) {
        return 1;
    }
    output_fp = fopen(output_path, "wb");
    if (output_fp == NULL) {
        printf("ERROR: unable to write to \"%s\".\n", output_path);
        return 1;
    }
    cover_fp = fopen(cover_path, "rb");
    if (cover_fp == NULL) {
        fclose(output_fp);
        printf("ERROR: unable to read from \"%s\".\n", cover_path);
        return 1;
    }
    if (!has_enough_lines(input_buf_size, cover_fp)) {
        printf("ERROR: the cover file must be larger.\n");
        fclose(output_fp);
        fclose(cover_fp);
        remove(output_path);
        return 1;
    }
    b = sizeof(input_buf_size) - 1;
    while (b > -1 && should_continue) {
        byte = input_buf_size >> (8 * b);
        should_continue = hide_byte(byte, cover_fp, output_fp);
        b--;
    }
    while (ip != ip_end && should_continue) {
        should_continue = hide_byte(*ip, cover_fp, output_fp);
        ip++;
    }
    if (should_continue) {
        while (hide_byte(0, cover_fp, output_fp));
    }
    fclose(output_fp);
    fclose(cover_fp);
    return (should_continue) ? 0 : 1;
}

static unsigned char recover_byte(FILE *input_fp) {
    unsigned char retval = 0;
    char *line = NULL;
    int b = 0;
    line = get_next_line_from_file(input_fp);
    while (!feof(input_fp) && line != NULL && b < 8) {
        retval = retval << 1 | get_bit_from_blank(line[strlen(line)-1]);
        b++;
        free(line);
        if (b < 8) {
            line = get_next_line_from_file(input_fp);
        }
    }
    return retval;
}

static int recover(FILE *input_fp, FILE *output_fp) {
    long output_size = 0;
    char *line = NULL;
    unsigned char byte = 0;
    int b = 0;
    if (input_fp == NULL) {
        return 1;
    }
    byte = recover_byte(input_fp);
    b = 0;
    output_size = 0;
    while (b < sizeof(output_size) && !feof(input_fp)) {
        output_size = output_size << 8 | byte;
        byte = recover_byte(input_fp);
        b++;
    }
    while (output_size-- > 0 && !feof(input_fp)) {
        fprintf(output_fp, "%c", byte);
        byte = recover_byte(input_fp);
    }
    return 0;
}

static char *get_option(const char *option, char **argv, int argc) {
    char temp[256];
    int a = 0;
    if (option == NULL || argv == NULL) {
        return NULL;
    }
    memset(temp, 0, sizeof(temp));
    strncpy(temp, "--", sizeof(temp) - 1);
    strncat(temp, option, sizeof(temp) - 1);
    strncat(temp, "=", sizeof(temp) - 1);
    for (a = 0; a < argc; a++) {
        if (strstr(argv[a], temp) == argv[a]) {
            return (&argv[a][0] + strlen(temp));
        }
    }
    return NULL;
}

int hide_stuff(int argc, char **argv) {
    FILE *fp = NULL;
    int exit_code = 1;
    char *option = NULL;
    char *input_buf = NULL;
    char *output_path = NULL;
    char *cover_path = NULL;
    size_t input_buf_size = 0;
    if ((option = get_option("input-path", argv, argc)) != NULL) {
        fp = fopen(option, "rb");
        if (fp == NULL) {
            printf("ERROR: unable to open the file \"%s\".\n", option);
            return 1;
        }
        fseek(fp, 0L, SEEK_END);
        input_buf_size = ftell(fp);
        fseek(fp, 0L, SEEK_SET);
        input_buf = (char *) malloc(input_buf_size + 1);
        if (input_buf == NULL) {
            printf("PANIC: no memory.\n");
            exit(1);
        }
        fread(input_buf, 1, input_buf_size, fp);
    } else if ((input_buf = get_option("input-buf", argv, argc)) != NULL) {
        input_buf_size = strlen(input_buf);
    } else {
        printf("OPTION PARSING ERROR: --input-path=<filepath> or --input-buf=<data> must be supplied.\n");
        return 1;
    }
    output_path = get_option("output-path", argv, argc);
    if (output_path == NULL) {
        printf("OPTION PARSING ERROR: --output-path=<filepath> must be supplied.\n");
        return 1;
    }
    cover_path = get_option("cover-path", argv, argc);
    if (cover_path == NULL) {
        printf("OPTION PARSING ERROR: --cover-path=<filepath> must be supplied.\n");
        return 1;
    }
/*    if (strcmp(input_path, cover_path) == 0 || strcmp(output_path, input_path) == 0 ||
        strcmp(cover_path, output_path) == 0) {
        printf("ERROR: --cover-path, --input-path and --output-path must point to different files.\n");
        return 1;
    }*/
    exit_code = hide(input_buf, input_buf_size, cover_path, output_path);
    if (fp != NULL) {
        fclose(fp);
        free(input_buf);
    }
    return exit_code;
}

int recover_stuff(int argc, char **argv) {
    char *input_path = NULL;
    char *output_path = NULL;
    FILE *fp = NULL;
    FILE *op = stdout;
    int exit_code = 1;
    input_path = get_option("input-path", argv, argc);
    if (input_path == NULL) {
        printf("OPTION PARSING ERROR: --input-path=<filepath> must be supplied.\n");
        return 1;
    }
    output_path = get_option("output-path", argv, argc);
    if (output_path != NULL && strcmp(input_path, output_path) == 0) {
        printf("ERROR: --input-path and --output-path must point to different files.\n");
        return 1;
    }
    fp = fopen(input_path, "rb");
    if (fp == NULL) {
        printf("ERROR: unable to read file \"%s\".\n", input_path);
        return 1;
    }
    if (output_path != NULL) {
        op = fopen(output_path, "wb");
        if (op == NULL) {
            fclose(fp);
            printf("ERROR: unable to write to \"%s\".\n", output_path);
            return 1;
        }
    }
    exit_code = recover(fp, op);
    fclose(fp);
    if (op != stdout) {
        fclose(op);
    }
    return exit_code;
}

int main(int argc, char **argv) {
    char *task = NULL;
    if (argc == 1) {
        printf(USAGE_TIP, argv[0]);
        return 1;
    }
    task = get_option("task", argv, argc);
    if (task == NULL) {
        printf("OPTION PARSING ERROR: --task=hide|recover must be supplied.\n");
        return 1;
    }
    if (strcmp(task, "hide") == 0) {
        return hide_stuff(argc, argv);
    } else if (strcmp(task, "recover") == 0) {
        return recover_stuff(argc, argv);
    } else {
        printf("OPTION PARSING ERROR: \"%s\" is a unknown task.\n", task);
        return 1;
    }
    return 0;
}
