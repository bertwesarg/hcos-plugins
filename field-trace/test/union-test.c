/* Field Trace field access hooks also support union fields.  It
   should treat them exactly as struct fields. */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test-harness-preamble.h"

/* Must define an expected[] array for test-harness.h to be
   meaningful. */
static struct expected_report expected[] = {
  SIMPLE_WRITE(foo, a, 0, 60),
  SIMPLE_WRITE(foo, b, 1, 61),
  SIMPLE_READ(foo, a, 0, 50),
  SIMPLE_READ(foo, b, 1, 51),
};

#include "test-harness.h"

union foo {
  int a;
  float b;
};

/* Field Trace does not add hooks for accesses to anonymous unions.
   It should not crash as a result of anonymous union accesses,
   however. */
union {
  uint32_t i;
  char v[4];
} anon;

noinstrument void __report_field_access(void *record_ptr, const char *record,
					const char *field, int field_index,
					int is_write, int is_marked,
					unsigned long bitmask, int *scratch,
					const char *filename, int lineno, int index)
{
  printf("%s reported, field %s (index %d)\n", (is_write ? "Write" : "Read"),
	 field, field_index);

  check_report(record_ptr, record, field, field_index, is_write, is_marked,
	       bitmask, scratch, filename, lineno);
}

void print_foo(union foo *foo)
{
  printf("%d\n", foo->a);
  printf("%f\n", foo->b);
}

int main()
{
  int i;

  union foo foo;
  expected_record_ptr = &foo;
  foo.a = 10;
  foo.b = 20.0f;

  anon.i = 123456;
  for (i = 0 ; i < 4 ; i++)
    printf("%d\n", anon.v[i]);

  print_foo(&foo);

  FINISH();
}
