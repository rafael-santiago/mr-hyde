#include <accacia.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define get_random_color(c, c_nr) ( c[rand() % (c_nr)] )

#define get_bit_from_byte(bit, byte) ( ( ( (byte) >> (bit) ) & 1 ) )

#define ascii_color2dec(ac) ( ( ( (*(ac)) - '0' ) * 10 ) + ( *(( (ac) + 1 )) - '0' ) )

#define get_byte_from_value(v, b) ( ( ( (v) >> ( ((sizeof((v)) * 8) - 8) - (8 * (b)) ) ) & 0xff ) )

static char *get_option(const char *option, const int argc, char **argv);

static int get_boolean_option(const char *option, const int argc, char **argv);

static ACCACIA_BACKGROUND_COLOR get_random_bkcolor();

static ACCACIA_TEXT_COLOR get_random_fgcolor();

static void hide_buf(const char *input_buf, const size_t input_size, const char *cover_buf, const size_t cover_size);

static const char *hide_bits(const unsigned char byte, const char *cover_buf, const char *cover_buf_end, const char *cover_buf_next);

static void recover_buf(const char *input_buf, const size_t input_size);

static ACCACIA_BACKGROUND_COLOR get_bkcolor_from_esc_code(const char *esc_code);

static ACCACIA_TEXT_COLOR get_fgcolor_from_esc_code(const char *esc_code);

static int little_endian_cpu();

static int little_endian_cpu() {
    int is = 1;
    return *(&is);
}

static const char *hide_bits(const unsigned char byte, const char *cover_buf, const char *cover_buf_end, const char *cover_buf_next) {
    const char *cp = cover_buf_next;
    int b = 0;
    ACCACIA_BACKGROUND_COLOR bk_color = AC_BCOLOR_BLACK;
    ACCACIA_TEXT_COLOR fg_color = AC_TCOLOR_BLACK;
    if (cp == NULL) {
        return NULL;
    }
    for (b = 7; b >= 0; b -= 2) {
        fg_color = (get_random_fgcolor() & (~1)) | get_bit_from_byte(b, byte);
        bk_color = (get_random_bkcolor() & (~1)) | get_bit_from_byte(b - 1, byte);
        while ((bk_color - fg_color) == 10) {
            fg_color = (get_random_fgcolor() & (~1)) | get_bit_from_byte(b, byte);
        }
        accacia_textcolor(fg_color);
        accacia_textbackground(bk_color);
        printf("%c", *cp);
        cp++;
        if (cp == cover_buf_end) {
            cp = cover_buf;
        }
    }
    return cp;
}

static void hide_buf(const char *input_buf, const size_t input_size, const char *cover_buf, const size_t cover_size) {
    const char *ip_end = NULL, *ip = NULL;
    const char *cp_end = NULL, *cp = NULL;
    int state = 0;

    if (input_buf == NULL || cover_buf == NULL) {
        return;
    }

    cp = cover_buf;
    cp_end = cp + cover_size;

    for (state = 0; state < 2; state++) {
        switch (state) {
            case 0:
                // INFO(Santiago): Hiding the plaintext input size.
                ip = (const char *) &input_size;
                ip_end = ip + sizeof(input_size);
                break;

            case 1:
                // INFO(Santiago): Hiding the plaintext.
                ip = input_buf;
                ip_end = ip + input_size;
                break;
        }
        while (ip != ip_end) {
            cp = hide_bits(*ip, cover_buf, cp_end, cp);
            ip++;
        }
    }

    // INFO(Santiago): Making sure that the whole cover buf will be used.
    while (cp != cp_end) {
        accacia_textcolor(get_random_fgcolor());
        accacia_textbackground(get_random_bkcolor());
        printf("%c", *cp);
        cp++;
    }
    accacia_screennormalize();
}

static ACCACIA_BACKGROUND_COLOR get_bkcolor_from_esc_code(const char *esc_code) {
    const char *ep = esc_code;
    ACCACIA_BACKGROUND_COLOR retcolor;
    if (ep == NULL || *ep != 27) {
        return AC_BCOLOR_BLACK;
    }
    ep += 2;
    if (*ep == '3') {
        ep += 3;
    }
    for (; *ep != 0 && *ep != '4'; ep++);
    retcolor = (*ep == '4') ? ascii_color2dec(ep) : AC_BCOLOR_BLACK;
    return retcolor;
}

static ACCACIA_TEXT_COLOR get_fgcolor_from_esc_code(const char *esc_code) {
    const char *ep = esc_code;
    ACCACIA_TEXT_COLOR retcolor;
    if (ep == NULL || *ep != 27) {
        return AC_TCOLOR_BLACK;
    }
    ep += 2;
    if (*ep == '4') {
        ep += 3;
    }
    for (; *ep != 0 && *ep != '3'; ep++);
    retcolor = (*ep == '3') ? ascii_color2dec(ep) : AC_TCOLOR_BLACK;
    return retcolor;
}

static void recover_buf(const char *input_buf, const size_t input_size) {
    size_t plaintext_size = 0, temp = 0;
    size_t b = 0;
    const char *ip = input_buf;
    const char *ip_end = ip + input_size;
    unsigned char byte = 0;
    if (ip == NULL) {
        return;
    }
    for (b = 0; b < (sizeof(plaintext_size) * 8) / 2 && ip < ip_end; b++) {
        if (ip >= ip_end) {
            continue;
        }
        plaintext_size = plaintext_size << 1 | (get_fgcolor_from_esc_code(ip) & 1);
        plaintext_size = plaintext_size << 1 | (get_bkcolor_from_esc_code(ip) & 1);
        ip += 11;
    }
    if (little_endian_cpu()) {
        temp = 0;
        for (b = 0; b < sizeof(plaintext_size); b++) {
            temp = (get_byte_from_value(plaintext_size, b) >> (8 * b)) | temp;
        }
        plaintext_size = temp;
    }
    if (plaintext_size > input_size) {
        return;
    }
    plaintext_size = (plaintext_size * 8) / 2;
    b = 0;
    while (ip < ip_end && plaintext_size-- > 0) {
        if (ip >= ip_end) {
            continue;
        }
        byte = byte << 1 | (get_fgcolor_from_esc_code(ip) & 1);
        byte = byte << 1 | (get_bkcolor_from_esc_code(ip) & 1);
        b += 2;
        if ((b + 1) > 8) {
            printf("%c", byte);
            b = 0;
        }
        ip += 11;
    }
}

static ACCACIA_BACKGROUND_COLOR get_random_bkcolor() {
    ACCACIA_BACKGROUND_COLOR colors[] = {
        AC_BCOLOR_BLACK,
        AC_BCOLOR_RED,
        AC_BCOLOR_GREEN,
        AC_BCOLOR_YELLOW,
        AC_BCOLOR_BLUE,
        AC_BCOLOR_MAGENTA,
        AC_BCOLOR_CYAN,
        AC_BCOLOR_WHITE
    };
    return get_random_color(colors, sizeof(colors) / sizeof(ACCACIA_BACKGROUND_COLOR));
}

static ACCACIA_TEXT_COLOR get_random_fgcolor() {
    ACCACIA_TEXT_COLOR colors[] = {
        AC_TCOLOR_BLACK,
        AC_TCOLOR_RED,
        AC_TCOLOR_GREEN,
        AC_TCOLOR_YELLOW,
        AC_TCOLOR_BLUE,
        AC_TCOLOR_MAGENTA,
        AC_TCOLOR_CYAN,
        AC_TCOLOR_WHITE
    };
    return get_random_color(colors, sizeof(colors) / sizeof(ACCACIA_TEXT_COLOR));
}

static char *get_option(const char *option, const int argc, char **argv) {
    int a = 0;
    char temp[255] = "";
    if (option == NULL) {
        return NULL;
    }
    strncpy(temp, "--", sizeof(temp) - 1);
    strncat(temp, option, sizeof(temp) - 1);
    strncat(temp, "=", sizeof(temp) - 1);
    for (a = 0; a < argc; a++) {
        if (strstr(argv[a], temp) == argv[a]) {
            return argv[a] + strnlen(temp, sizeof(temp) - 1);
        }
    }
    return NULL;
}

static int get_boolean_option(const char *option, const int argc, char **argv) {
    int a = 0;
    char temp[255] = "";
    if (option == NULL) {
        return 0;
    }
    strncpy(temp, "--", sizeof(temp) - 1);
    strncat(temp, option, sizeof(temp) - 1);
    for (a = 0; a < argc; a++) {
        if (strcmp(argv[a], temp) == 0) {
            return 1;
        }
    }
    return 0;
}

int hide_user_stuff(int argc, char **argv) {
    char *option = NULL;
    char *input_buf = NULL, *cover_buf = NULL;
    long input_size = 0, cover_size = 0;
    FILE *fp = NULL;
    size_t a = 0;
    int retval = 1;
    if ((option = get_option("input-file", argc, argv)) != NULL) {
        fp = fopen(option, "rb");
        if (fp == NULL) {
            printf("ERROR: unable to read data from \"%s\".\n", option);
            goto ___hide_user_stuff_fini;
        }
        fseek(fp, 0L, SEEK_END);
        input_size = ftell(fp);
        fseek(fp, 0L, SEEK_SET);
        input_buf = (char *) malloc(input_size + 1);
        memset(input_buf, 0, input_size + 1);
        fread(input_buf, sizeof(char), input_size, fp);
        fclose(fp);
    } else if ((option = get_option("input-buf", argc, argv)) != NULL) {
        input_size = strlen(option);
        input_buf = option;
    } else {
        printf("ERROR: for hiding issues you need to specify the input buffer using \"--input-file=<filepath>\" or \"--input-buf=<data>\".\n");
        goto ___hide_user_stuff_fini;
    }
    if ((option = get_option("cover-file", argc, argv)) != NULL) {
        fp = fopen(option, "rb");
        if (fp == NULL) {
            printf("ERROR: unable to read data from \"%s\".\n", option);
            goto ___hide_user_stuff_fini;
        }
        fseek(fp, 0L, SEEK_END);
        cover_size = ftell(fp);
        fseek(fp, 0L, SEEK_SET);
        cover_buf = (char *) malloc(cover_size + 1);
        memset(cover_buf, 0, cover_size + 1);
        fread(cover_buf, sizeof(char), cover_size, fp);
        fclose(fp);
    } else if ((option = get_option("cover-buf", argc, argv)) != NULL) {
        cover_size = strlen(option);
        cover_buf = option;
    } else {
        printf("ERROR: for hiding issues you need to specify the cover buffer using \"--cover-file=<filepath>\" or \"--cover-buf=<data>\".\n");
        goto ___hide_user_stuff_fini;
    }
    hide_buf(input_buf, input_size, cover_buf, cover_size);
    printf("\n");
    retval = 0;
___hide_user_stuff_fini:
    for (cover_size = 0; cover_size < 2; cover_size++) {
        switch (cover_size) {
            case 0:
                option = input_buf;
                input_size = strlen("--input-buf=");
                break;

            case 1:
                option = cover_buf;
                input_size = strlen("--cover-buf=");
                break;
        }
        for (a = 0; a < argc && option != NULL; a++) {
            if ((option == argv[a] + input_size)) {
                option = NULL;
            }
        }
        free(option); // INFO(Santiago): Are you running it in a pretty old UNIX box?? Please, let me know!! :)
    }
    return retval;
}

int recover_user_stuff(int argc, char **argv) {
    char *option = NULL;
    char *input_buf = NULL;
    long input_size = 0;
    FILE *fp = NULL;
    if ((option = get_option("input-file", argc, argv)) != NULL) {
        fp = fopen(option, "rb");
        if (fp == NULL) {
            printf("ERROR: unable to read file \"%s\".\n", option);
            return 1;
        }
        fseek(fp, 0L, SEEK_END);
        input_size = ftell(fp);
        fseek(fp, 0L, SEEK_SET);
        input_buf = (char *) malloc(input_size + 1);
        memset(input_buf, 0, input_size + 1);
        fread(input_buf, sizeof(char), input_size, fp);
        fclose(fp);
        option = input_buf;
    } else if ((option = get_option("input-buf", argc, argv)) != NULL) {
        input_buf = option;
        input_size = strlen(option);
        option = NULL;
    } else {
        printf("ERROR: for recovering issues you need to specify the input buffer using \"--input-file=<filepath>\" or \"--input-buf=<data>.\n");
        return 1;
    }
    recover_buf(input_buf, input_size);
    printf("\n");
    free(option); // INFO(Santiago): Are you running it in a pretty old UNIX box?? Please, let me know!! :)
    return 0;
}

int main(int argc, char **argv) {
    srand(time(0));
    char *option = NULL;
    if (get_boolean_option("help", argc, argv)) {
        printf("usage: %s --task=hide|recover --input-file=<filepath>|--input-buf=<data> --cover-file=<filepath>|--cover-buf=<data>\n", argv[0]);
        return 0;
    }
    option = get_option("task", argc, argv);
    if (option == NULL) {
        printf("ERROR: what do you want to do? Do you want to hide? -> \"--task=hide\". Do you want to recover? -> \"--task=recover\".\n");
        return 1;
    }
    if (strcmp(option, "hide") != 0 && strcmp(option, "recover") != 0) {
        printf("ERROR: \"%s\" is a unknown task.\n", option);
        return 1;
    }
    if (strcmp(option, "hide") == 0) {
        return hide_user_stuff(argc, argv);
    }
    return recover_user_stuff(argc, argv);
}
