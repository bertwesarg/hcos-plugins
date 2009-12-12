/* When a variable gets an instrumented struct type through a typedef,
   we still want to instrument it. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test-harness-preamble.h"

/* Must define an expected[] array for test-harness.h to be
   meaningful. */
static struct expected_report expected[] = {
  SIMPLE_WRITE(foo, field1, 0, 49),
  SIMPLE_WRITE(foo, field2, 1, 50),
};

#include "test-harness.h"

typedef struct foo {
  int field1;
  int field2;
} foo_typedef;

noinstrument void __report_field_access(void *record_ptr, const char *record,
					const char *field, int field_index,
					int is_write, int is_marked,
					unsigned long bitmask, int *scratch,
					const char *filename, int lineno)
{
  int *field_val = (int *)record_ptr;
  printf("At %s:%d\n", filename, lineno);
  printf("Field access: %s[Index: %d] >>>> %s (Value: %d) [%s]\n",
	 record,
	 field_index,
	 field,
	 *field_val,
	 is_write ? "write" : "read");

  check_report(record_ptr, record, field, field_index, is_write, is_marked,
	       bitmask, scratch, filename, lineno);
}

int main()
{
  volatile foo_typedef my_foo;

  expected_record_ptr = (void *)&my_foo;

  my_foo.field1 = 10;
  my_foo.field2 = 20;

  FINISH();
}
