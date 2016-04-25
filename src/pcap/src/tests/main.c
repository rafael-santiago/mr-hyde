#include <cutest.h>
#include "../pktslicer.h"

CUTE_TEST_CASE(pktslicer_tests)

CUTE_TEST_CASE_END

CUTE_TEST_CASE(run_tests)
    CUTE_RUN_TEST(pktslicer_tests);
CUTE_TEST_CASE_END

CUTE_MAIN(run_tests)
