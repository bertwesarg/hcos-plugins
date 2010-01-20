/* This test case duplicates a statement in the msr_open() kernel
   function that triggered a bug.  The left operand of the
   COMPONENT_REF that GCC generates for this test case is not a DECL
   node, and should not be shared.  The fix for the bug involves
   copying the node with stabilize_reference().

   This test case was originally created when this plug-in targeted
   GCC 4.3.0, but upon porting the plug-in and its test cases, it
   tickled a new bug!

   The arguments to a GIMPLE_CALL should never be a an ADDR_EXPR of
   any kind of decl.  Instead, we now assign that ADDR_EXPR to a temp
   variable and pass its SSA name as the argument. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test-harness-preamble.h"

/* Must define an expected[] array for test-harness.h to be
   meaningful. */
static struct expected_report expected[] = {
  SIMPLE_WRITE(foo, a, 0, 81),
  SIMPLE_READ(foo, a, 0, 69),
};

#include "test-harness.h"

struct foo {
  int a;
  int b;
};

struct level3 {
  struct foo* foo;
  int e;
  int f;
};

struct level2 {
  struct level3 *next;
  int c;
  int d;
};

struct level1 {
  struct level2 next;
  int a;
  int b;
};

noinstrument void __report_field_access(void *record_ptr, const char *record,
					const char *field, int field_index,
					int is_write, int is_marked,
					unsigned long bitmask, int *scratch,
					const char *filename, int lineno, int index)
{
  int i = *((int *)record_ptr);
  printf("Access reported with foo.a = %d\n", i);

  check_report(record_ptr, record, field, field_index, is_write, is_marked,
	       bitmask, scratch, filename, lineno);
}

static inline int read_a(struct foo *) __attribute__ ((always_inline));

static inline int read_a(struct foo *data) {
  return data->a;
}

void func() {
  struct foo foo;
  struct level3 level3;
  struct level1 level1;

  struct level1 *startptr = &level1;

  expected_record_ptr = (void *)&foo;

  foo.a = 10;

  /* Defeats some optimizations. */
  startptr += 1;
  startptr -= 1;

  startptr->next.next = &level3;
  startptr->next.next->foo = &foo;

  int i = read_a(startptr->next.next->foo);

  printf("%d\n", i);
}

int main() {
  func();
  FINISH();
}
