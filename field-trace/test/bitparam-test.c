/* Test for a weird case when a bitmask gets defined after the field
   reference it masks.  The conditional in test_bitmask becomes GIMPLE
   that looks like this:

   1: tmp.bitmask = tmp2;
   2: tmp.record_addr = foo;
   3: __report_field_access(tmp.record_addr, tmp.bitmask, ...);
   4: tmp1 = foo->i_state;
   5: tmp2 = bitmask;

   Statement 1 tries to use the definition in statement 5, which is
   out of order.  We need to move statement 5 up to be before
   statement 1! */

/* This test case is no longer useful because we simplified bitmask
   handling to require that the bitmask be the problem.  That solves
   the problem, but it also breaks this test case, which is now
   expected to fail. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test-harness-preamble.h"

/* Must define an expected[] array for test-harness.h to be
   meaningful. */
static struct expected_report expected[] = {
  BITMASK_READ(foo, i_state, 2, 8, 51),
};

#include "test-harness.h"

struct foo {
  int bar;
  int baz;
  unsigned long i_state;
};

noinstrument void __report_field_access(void *record_ptr, const char *record,
					const char *field, int field_index,
					int is_write, int is_marked,
					unsigned long bitmask, int *scratch,
					const char *filename, int lineno,
					int index, int struct_index)
{
  printf("Struct %s with bitmask: 0x%08lx\n", (is_write ? "assign" : "access"),
	 bitmask);

  check_report(record_ptr, record, field, field_index, is_write, is_marked,
	       bitmask, scratch, filename, lineno);
}

__attribute__((noinline)) void test_bitmask(struct foo *foo, int bitmask)
{
  if (foo->i_state & bitmask) {
    printf("Tested state.\n");
  }

  printf("Leaving test_bitmask.\n");
}

noinstrument int main()
{
  struct foo foo;

  expected_record_ptr = &foo;

  foo.i_state = 0xffff;
  test_bitmask(&foo, 8);

  return 0;
}
