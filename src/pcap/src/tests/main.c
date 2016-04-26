#include <cutest.h>
#include "../pktslicer.h"

CUTE_TEST_CASE(pktslicer_tests)
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
    CUTE_RUN_TEST(pktslicer_tests);
CUTE_TEST_CASE_END

CUTE_MAIN(run_tests)
