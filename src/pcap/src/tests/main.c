#include <cutest.h>
#include <string.h>
#include "pcap_data.h"
#include "../pktslicer.h"
#include "../pcap.h"
#include "../steg.h"
#include "../chsum.h"

void printp(unsigned char *p, size_t ps) {
    size_t s;
    for (s = 0; s < ps; s++) printf("%.2x ", p[s]);
    printf("\n");
}

CUTE_TEST_CASE(chsum_tests)
    unsigned char ip_packet[] = {
        "\x45\x00\x00\x34\xc8\xc5\x40\x00\x3a\x06\x00\x00\x17\x2d\xdc\x5e\xc0\xa8\x01\x4b"
    };
    size_t ip_packet_size = 20;
    unsigned char tcp_packet[] = {
        "\x00\x50\x04\x59\x60\x26\x26\xa7\xba\x84\x24\x9b\x80\x10"
        "\x03\x9c\x00\x00\x00\x00\x01\x01\x05\x0a\xba\x84\x24\x9a"
        "\xba\x84\x24\x9b"
    };
    size_t tcp_packet_size = 32;
    unsigned char wire_buf[] = {
        "\x5c\xac\x4c\xaa\xf5\xb5\x08\x95\x2a\xad\xd6\x4f\x08\x00\x45\x00"
        "\x00\x34\xc8\xc5\x40\x00\x3a\x06\xff\xff\x17\x2d\xdc\x5e\xc0\xa8"
        "\x01\x4b\x00\x50\x04\x59\x60\x26\x26\xa7\xba\x84\x24\x9b\x80\x10"
        "\x03\x9c\xff\xff\x00\x00\x01\x01\x05\x0a\xba\x84\x24\x9a\xba\x84"
        "\x24\x9b"
    };
    size_t wire_buf_size = 66;
    unsigned char *chsum = NULL;
    CUTE_ASSERT(ip_chsum(ip_packet, ip_packet_size) == 0xc27f);
    unsigned short c;
    CUTE_ASSERT(tcp_chsum(tcp_packet, tcp_packet_size, "\x17\x2d\xdc\x5e", 4, "\xc0\xa8\x01\x4b", 4, 32) == 0x97cd);
    reval_tcp_ip_chsums(wire_buf, wire_buf_size);
    chsum = get_pkt_field("ip.chsum", wire_buf, wire_buf_size, NULL);
    CUTE_ASSERT(chsum != NULL && *chsum == 0xc2 && *(chsum + 1) == 0x7f);
    chsum = get_pkt_field("tcp.chsum", wire_buf, wire_buf_size, NULL);
    CUTE_ASSERT(chsum != NULL && *chsum == 0x97 && *(chsum + 1) == 0xcd);
CUTE_TEST_CASE_END


CUTE_TEST_CASE(pcap_loading_tests)
    FILE *pcap = fopen("pcap-test.pcap", "wb");
    pcap_file_ctx *pcap_file = NULL;
    CUTE_ASSERT(pcap != NULL);
    fwrite(pcap_data, 1, pcap_data_size, pcap);
    fclose(pcap);
    pcap_file = ld_pcap_file("marklar.pcap");
    CUTE_ASSERT(pcap_file == NULL);
    pcap_file = ld_pcap_file("pcap-test.pcap");
    CUTE_ASSERT(pcap_file != NULL && pcap_file->rec != NULL);
    close_pcap_file(pcap_file);
    pcap_file = NULL;
    remove("pcap-test.pcap");
CUTE_TEST_CASE_END

CUTE_TEST_CASE(steg_tests)
    FILE *pcap = fopen("pcap-test.pcap", "wb");
    char *input_buf = "boo.";
    char *output_buf = NULL;
    size_t input_buf_size = 4;
    size_t output_buf_size = 0;
    struct steg_test_vector {
        const char *input_buf;
    };
    struct steg_test_vector test_data [] = {
        { "boo."                                                                                     },
        { "Hey Beavis, I am a hidden string! huh!"                                                   },
        { "ABCd."                                                                                    },
        { "The lazy fox.... slept!"                                                                  },
        { "All work and no play makes jake a dull boy."                                              },
        { "a"                                                                                        },
        { "\"ahhhhhhhhhhhhhhhhhhhhhhhh...\""                                                         },
        { ""                                                                                         },
        { "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ."                                    },
        { "Mundo, mundo, vasto mundo"                                                                },
        { "se eu me chamasse Raimundo"                                                               },
        { "seria apenas uma rima"                                                                    },
        { "nao seria uma solucao"                                                                    },
        { "um homem com uma dor"                                                                     },
        { "e muito mais elegante"                                                                    },
        { "caminha assim de lado"                                                                    },
        { "como se chegando atrasado"                                                                },
        { "andasse mais adiante"                                                                     },
        { "carrega o peso da dor"                                                                    },
        { "como se portasse medalhas"                                                                },
        { "um milhao de dolares"                                                                     },
        { "ou coisa que os valha"                                                                    },
        { "opios, edens, analgesicos nao me toquem nessa dor"                                        },
        { "ela e tudo o que me sobra"                                                                },
        { "sofrer vai ser a minha ultima"                                                            },
        { "obra"                                                                                     },
        { "para que cara feia, na vida ninguem paga meia"                                            },
        { "moinhos de versos movidos a poesia, vai vir um dia em que tudo o que eu diga seja poesia" },
        { "a esperanca e um urubu pintado de verde"                                                  },
        { "When I think about myself"                                                                },
        { "I almost laugh myself to death"                                                           },
        { "My life has been one great big joke"                                                      },
        { "A dance that's walked"                                                                    },
        { "A song that's spoke"                                                                      },
        { "I laugh so hard I almost choke"                                                           },
        { "When I think about myself"                                                                },
        { "Sixty years in these folks' world"                                                        },
        { "The child I works for calls me girl"                                                      },
        { "I say \"Yes ma'am\" for working sake"                                                     },
        { "Too proud to bend"                                                                        },
        { "Too poor to break"                                                                        },
        { "I laugh until my stomach ache,"                                                           },
        { "When I think about myself."                                                               },
        { "My folks can make me split my side,"                                                      },
        { "I laughed so hard I nearly died,"                                                         },
        { "The tales they tell, sound just like lying,"                                              },
        { "They grow the fruit,"                                                                     },
        { "But eat the rind,"                                                                        },
        { "I laugh until I start to crying,"                                                         },
        { "When I think about my folks."                                                             },
        { "Aos que me dao lugar no bonde"                                                            },
        { "E que conheço nao sei de onde."                                                           },
        { "Aos que me dizem terno adeus"                                                             },
        { "Sem que lhes saiba os nomes seus,"                                                        },
        { "Aos que, de bons, se babam, mestre!"                                                      },
        { "Inda se escrevo o que nao preste"                                                         },
        { "Aos que me julgam primo-irmao"                                                            },
        { "Do rei da fava ou do hindustao"                                                           },
        { "Aos que me pensam milionario"                                                             },
        { "Se pego aumento de salario"                                                               },
        { "- e aos que me negam cumprimento"                                                         },
        { "Sem o mais minimo argumento."                                                             },
        { "Aos que nao sabem que eu existo."                                                         },
        { "Ate mesmo quando os assisto."                                                             },
        { "Aos que me trancam sua cara"                                                              },
        { "De carinho alergica e avara,"                                                             },
        { "Aos que me tacham de ultrabeocia"                                                         },
        { "A pretensao de vir da escocia,"                                                           },
        { "Aos que vomitam (sic) meus poemas"                                                        },
        { "Nos mais simples vendo problemas,"                                                        },
        { "Aos que, sabendo-me mais pobre,"                                                          },
        { "Me negariam pano ou cobre"                                                                },
        { "- eu agradeço humildemente"                                                               },
        { "Gesto assimm vario e divergente"                                                          },
        { "Graças ao qual, em dois minutos,"                                                         },
        { "Tal como o fumo dos charutos,"                                                            },
        { "Ja subo aos ceus, ja volvo ao chao,"                                                      },
        { "Pois tudo e nada nada sao."                                                               },
        { "things have come to a pretty pass"                                                        },
        { "our romance is growing flat"                                                              },
        { "for you like this and the other"                                                          },
        { "while I go for this and that"                                                             },
        { "goodness knows what the end will be"                                                      },
        { "oh I don't know where i'm at"                                                             },
        { "it looks as if we two will never be one"                                                  },
        { "something must be done:"                                                                  },
        { "you say either and I say either"                                                          },
        { "you say neither and I say neither"                                                        },
        { "either, either, neither, neither"                                                         },
        { "let's call the whole thing off"                                                           },
        { "you like potato and I like potahto"                                                       },
        { "you like tomato and I like tomahto"                                                       },
        { "potato, potahto, tomato, tomahto"                                                         },
        { "let's call the whole thing off"                                                           },
        { "but oh, if we call the whole thing off"                                                   },
        { "then we must part"                                                                        },
        { "and oh, if we ever part, then that might break my heart"                                  },
        { "so if you like pyjamas and I like pyjahmas,"                                              },
        { "I'll wear pyjamas and give up pyjhamas"                                                   },
        { "for we know we need each other so we"                                                     },
        { "better call the whole thing off"                                                          },
        { "let's call the whole thing off"                                                           },
        { "you say laughter and I say larfter"                                                       },
        { "you say after and I say arfter"                                                           },
        { "laughter, larfter after arfter"                                                           },
        { "let's call the whole thing off"                                                           },
        { "you like vanilla and I like vanella"                                                      },
        { "you saspiralla, and I saspirella"                                                         },
        { "vanilla vanella chocolate strawberry"                                                     },
        { "let's call the whole thing off"                                                           },
        { "but oh if we call the whole thing off then we must part"                                  },
        { "and oh, if we ever part, then that might break my heart"                                  },
        { "so if you go for oysters and I go for ersters"                                            },
        { "I'll order oysters and cancel the ersters"                                                },
        { "for we know we need each other so we"                                                     },
        { "better call the calling off off,"                                                         },
        { "let's call the whole thing off."                                                          },
        { "I say father, and you say pater,"                                                         },
        { "I saw mother and say mater"                                                               },
        { "pater, mater uncle, auntie let's call the whole thing off."                               },
        { "I like bananas and you like banahnahs"                                                    },
        { "I say Havana and I get Havahnah"                                                          },
        { "bananas, banahnahs havanam havahnah"                                                      },
        { "go your way, I'll go mine"                                                                },
        { "so if I go for scallops and you go for lobsters,"                                         },
        { "so all right no contest we'll order lobster"                                              },
        { "for we know we need each other so we"                                                     },
        { "better call the calling off off,"                                                         },
        { "let's call the whole thing off."                                                          },
        { "ain't got the change if a nickel"                                                         },
        { "ain't got no bounce in my shoes"                                                          },
        { "ain't go no fancy to tickle"                                                              },
        { "I ain't got nothing but the blues"                                                        },
        { "ain't got no coffe that's perking"                                                        },
        { "ain't got no winnings to lose"                                                            },
        { "ain't got a dream that is working"                                                        },
        { "I ain't got nothing but the blues"                                                        },
        { "when trumpets flare up"                                                                   },
        { "I keep my hair up"                                                                        },
        { "I just can't make it come down"                                                           },
        { "believe me peppie"                                                                        },
        { "I can't get happy"                                                                        },
        { "since my ever loving babe left town"                                                      },
        { "ain't got no rest in my slumbers"                                                         },
        { "ain't got no feelings to bruise"                                                          },
        { "ain't got no telephone numbers"                                                           },
        { "I ain't got nothing but the blues."                                                       },
        { "I've got the world on a string, sittin' on a rainbow"                                     },
        { "Got the string around my finger"                                                          },
        { "What a world, what a life, I'm in love"                                                   },
        { "I've got a song that I sing"                                                              },
        { "I can make the rain go, anytime I move my finger"                                         },
        { "Lucky me, can't you see, I'm in love"                                                     },
        { "Life is a beautiful thing, as long as I hold the string"                                  },
        { "I'd be a silly so and so, if I should ever let it go"                                     },
        { "I've got the world on a string, sittin' on a rainbow"                                     },
        { "Got the string around my finger"                                                          },
        { "What a world, what a life, I'm in love"                                                   },
        { "Life is a beautiful thing, as long as I hold the string"                                  },
        { "I'd be a silly so and so, if I should ever let it go"                                     },
        { "I've got the world on a string, sittin' on a rainbow"                                     },
        { "Got the string around my finger"                                                          },
        { "What a world"                                                                             },
        { "Man this is the life"                                                                     },
        { "Hey now I'm so in love"                                                                   },
        { "essa musica eu tava cantando ali na cidade grande ai e"                                   },
        { "um soldado gostou tanto que me levou pra canta na cadeia"                                 },
        { "florentina o nome dela."                                                                  },
        { "florentina, florentina"                                                                   },
        { "florentina de jesus"                                                                      },
        { "nao sei se tu me amas"                                                                    },
        { "pra que tu me seduz"                                                                      },
        { "eu tava cantando e o soldado disse"                                                       },
        { "\"rapaz tu canta muito bora canta na cadeia?\""                                           },
        { "chego la me empurrou ai tinha"                                                            },
        { "um loirao muito doido la dentro"                                                          },
        { "o loiro olho pra mim e falou:"                                                            },
        { "\"qual e? qual foi? Porque que tu ta nessa?\""                                            },
        { "eu disse nao so pusque eu tava cantando:"                                                 },
        { "florentina, florentina"                                                                   },
        { "florentina de jesus"                                                                      },
        { "nao sei se tu me amas"                                                                    },
        { "pra que tu me seduz"                                                                      },
        { "ele falou: \"pode cre meu, cala tua boca senao eu boto seus dente pa drento!\""           },
        { "fiquei bem caladinho"                                                                     },
        { "quando foi no outro dia o dregolado falou:"                                               },
        { "\"quem e o cantor?\" eu disse pronto..."                                                  },
        { "rapaz voce ta solto!"                                                                     },
        { "mas nunca mais cante esse negocio de:"                                                    },
        { "florentina, florentina"                                                                   },
        { "florentina de jesus"                                                                      },
        { "nao sei se tu me amas"                                                                    },
        { "pra que tu me seduz"                                                                      },
        { "graças a deus, desde este dia pra ca nunca mais eu cantei esse negocio de:"               },
        { "florentina, florentina"                                                                   },
        { "florentina de jesus"                                                                      },
        { "nao sei se tu me amas"                                                                    },
        { "pra que tu me seduz"                                                                      },
        { "chega de tanta..."                                                                        },
        { "florentina, florentina"                                                                   },
        { "florentina de jesus"                                                                      },
        { "nao sei se tu me amas"                                                                    },
        { "pra que tu me seduz"                                                                      },
        { "isso e uma coisa que todo mundo abusa esse negocio de:"                                   },
        { "florentina, florentina"                                                                   },
        { "florentina de jesus"                                                                      },
        { "nao sei se tu me amas"                                                                    },
        { "pra que tu me seduz"                                                                      },
        { "agora eu ja parei com esse negocio de:"                                                   },
        { "florentina, florentina"                                                                   },
        { "florentina de jesus"                                                                      },
        { "nao sei se tu me amas"                                                                    },
        { "pra que tu me seduz"                                                                      },
        { "agora eu vou canta pra voces uma musica de roberto carlos que chama:"                     },
        { "florentina, florentina"                                                                   },
        { "florentina de jesus"                                                                      },
        { "nao sei se tu me amas"                                                                    },
        { "pra que tu me seduz"                                                                      }
    }; //  INFO(Santiago): Yes, I want to stress it too!
    size_t test_data_size = sizeof(test_data) / sizeof(test_data[0]), t = 0;
    pcap_file_ctx *pcap_file = NULL;
    CUTE_ASSERT(pcap != NULL);
    fwrite(pcap_data, 1, pcap_data_size, pcap);
    fclose(pcap);


    for (t = 0; t < test_data_size; t++) {
        pcap_file = ld_pcap_file("pcap-test.pcap");
        CUTE_ASSERT(pcap_file != NULL);
        input_buf_size = strlen(test_data[t].input_buf);
        CUTE_ASSERT(hide_buf(test_data[t].input_buf, input_buf_size, &pcap_file) == 1);
        output_buf = recover_buf(pcap_file, &output_buf_size);
        CUTE_ASSERT(output_buf != NULL);
        CUTE_ASSERT(output_buf_size == input_buf_size);
        CUTE_ASSERT(strcmp(output_buf, test_data[t].input_buf) == 0);
        free(output_buf);
        close_pcap_file(pcap_file);
        pcap_file = NULL;
    }

    remove("pcap-test.pcap");
CUTE_TEST_CASE_END

CUTE_TEST_CASE(pktslicer_set_pkt_field_tests)
    unsigned char packet[] = {
        "\x5c\xac\x4c\xaa\xf5\xb5\x08\x95\x2a\xad\xd6\x4f\x08\x00\x45\x00"
        "\x00\x34\xc8\xc5\x40\x00\x3a\x06\xc2\x7f\x17\x2d\xdc\x5e\xc0\xa8"
        "\x01\x4b\x00\x50\x04\x59\x60\x26\x26\xa7\xba\x84\x24\x9b\x80\x10"
        "\x03\x9c\x97\xcd\x00\x00\x01\x01\x05\x0a\xba\x84\x24\x9a\xba\x84"
        "\x24\x9b"
    };
    size_t packet_size = 66;
    unsigned int value = 0x81;
    int *slice = NULL;

    slice = get_pkt_field("tcp.reserv", packet, packet_size, NULL);
    CUTE_ASSERT(slice != NULL);
    CUTE_ASSERT(*slice == 0);
    set_pkt_field("tcp.reserv", packet, packet_size, (*slice & (~1)) | value);
    slice = get_pkt_field("tcp.reserv", packet, packet_size, NULL);
    CUTE_ASSERT(slice != NULL);
    CUTE_ASSERT(*(unsigned int *)slice == 4);

    value = 0x0000ffff;
    slice = get_pkt_field("ip.chsum", packet, packet_size, NULL);
    CUTE_ASSERT(slice != NULL);
    CUTE_ASSERT((*slice & 0x0000ffff) == 0x7fc2);
    set_pkt_field("ip.chsum", packet, packet_size, value);
    slice = get_pkt_field("ip.chsum", packet, packet_size, NULL);
    CUTE_ASSERT(slice != NULL);
    CUTE_ASSERT((*slice & 0x0000ffff) == 0xffff);

    slice = get_pkt_field("tcp.chsum", packet, packet_size, NULL);
    CUTE_ASSERT(slice != NULL);
    CUTE_ASSERT((*slice & 0x0000ffff) == 0xcd97);
    set_pkt_field("tcp.chsum", packet, packet_size, value);
    slice = get_pkt_field("tcp.chsum", packet, packet_size, NULL);
    CUTE_ASSERT(slice != NULL);
    CUTE_ASSERT((*slice & 0x0000ffff) == 0xffff);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(pktslicer_get_pkt_field_tests)
    char *packet = "\x5c\xac\x4c\xaa\xf5\xb5\x08\x95\x2a\xad\xd6\x4f\x08\x00\x45\x00"
                   "\x00\x34\xc8\xc5\x40\x00\x3a\x06\xc2\x7f\x17\x2d\xdc\x5e\xc0\xa8"
                   "\x01\x4b\x00\x50\x04\x59\x60\x26\x26\xa7\xba\x84\x24\x9b\x80\x10"
                   "\x03\x9c\x97\xcd\x00\x00\x01\x01\x05\x0a\xba\x84\x24\x9a\xba\x84"
                   "\x24\x9b";
    size_t packet_size = 66;
    size_t slice_size = 0;
    void *slice = NULL;
    struct expect_slices {
        const size_t slice_size;
        const unsigned char *slice;
        const char *pkt_field;
    };
    struct expect_slices slices[] = {
        { 6, "\x5c\xac\x4c\xaa\xf5\xb5", "eth.dst"    },
        { 6, "\x08\x95\x2a\xad\xd6\x4f", "eth.src"    },
        { 2, "\x08\x00",                 "eth.type"   },
        { 1, "\x04",                     "ip.version" },
        { 1, "\x05",                     "ip.ihl"     },
        { 1, "\x00",                     "ip.tos"     },
        { 2, "\x00\x34",                 "ip.len"     },
        { 2, "\xc8\xc5",                 "ip.id"      },
        { 1, "\x02",                     "ip.flags"   },
        { 2, "\x00\x00",                 "ip.fragoff" },
        { 1, "\x3a",                     "ip.ttl"     },
        { 1, "\x06",                     "ip.proto"   },
        { 2, "\xc2\x7f",                 "ip.chsum"   },
        { 4, "\x17\x2d\xdc\x5e",         "ip.src"     },
        { 4, "\xc0\xa8\x01\x4b",         "ip.dst"     },
        { 2, "\x00\x50",                 "tcp.src"    },
        { 2, "\x04\x59",                 "tcp.dst"    },
        { 4, "\x60\x26\x26\xa7",         "tcp.seqno"  },
        { 4, "\xba\x84\x24\x9b",         "tcp.ackno"  },
        { 1, "\x08",                     "tcp.len"    },
        { 1, "\x00",                     "tcp.reserv" },
        { 1, "\x0010",                   "tcp.flags"  },
        { 2, "\x03\x9c",                 "tcp.window" },
        { 2, "\x97\xcd",                 "tcp.chsum"  },
        { 2, "\x00\x00",                 "tcp.urgp"   }
    };
    size_t slices_nr = sizeof(slices) / sizeof(slices[0]), s = 0;
    size_t b = 0;

    slice = get_pkt_field("unk.field", packet, packet_size, &slice_size);
    CUTE_ASSERT(slice == NULL);
    CUTE_ASSERT(slice_size == 0);

    slice = get_pkt_field("unk.field", packet, packet_size, NULL);
    CUTE_ASSERT(slice == NULL);

    for (s = 0; s < slices_nr; s++) {
        slice = get_pkt_field(slices[s].pkt_field, packet, packet_size, &slice_size);
        CUTE_ASSERT(slice_size == slices[s].slice_size);
        CUTE_ASSERT(slice != NULL);
        for (b = 0; b < slice_size; b++) {
            CUTE_ASSERT(((unsigned char *)slice)[b] == slices[s].slice[b]);
        }
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(run_tests)
    CUTE_RUN_TEST(pktslicer_get_pkt_field_tests);
    CUTE_RUN_TEST(pktslicer_set_pkt_field_tests);
    CUTE_RUN_TEST(pcap_loading_tests);
    CUTE_RUN_TEST(chsum_tests);
    CUTE_RUN_TEST(steg_tests);
CUTE_TEST_CASE_END

CUTE_MAIN(run_tests)
