#include <rz_util.h>
#include "minunit.h"
#include "librz/asm/arch/java/code.h"
#include "librz/bin/format/java/class.h"
#include "librz/bin/format/java/print.h"
#include "librz/bin/format/java/json.h"

bool test_rz_java(void) {
	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_java);
	return tests_passed != tests_run;
}

mu_main(all_tests)