/* A simple test that exercises Hook insertions for field acceses. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test-harness-preamble.h"

/* Must define an expected[] array for test-harness.h to be
   meaningful. */
static struct expected_report expected[] = {
  SIMPLE_WRITE(foo, field2, 1, 58),
  SIMPLE_WRITE(foo, field2, 1, 59),
  SIMPLE_READ(foo, field1, 0, 59),
  SIMPLE_WRITE(foo, field1, 0, 59),
  SIMPLE_WRITE(foo, field1, 0, 59),
  SIMPLE_WRITE(foo, field1, 0, 59),
  SIMPLE_WRITE(foo, field1, 0, 59),
  SIMPLE_WRITE(foo, field1, 0, 59),
};

#include "test-harness.h"

struct foo {
  int field1;
  int field2;
};

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
  volatile struct foo my_foo;
  volatile struct foo *ptr;
  volatile struct foo **ptr2;

  expected_record_ptr = &my_foo;

  my_foo.field2 = 10;
  my_foo.field2 = 20;

  /* This should get reported as a read then a write. */
  my_foo.field1++;

  ptr = &my_foo;
  ptr->field1 = 10;
  (*ptr).field1 = 20;

  ptr2 = &ptr;
  (*ptr2)->field1 = 10;
  (*ptr2)->field1 = 20;

  return 0;
}
