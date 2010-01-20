/* We want to report accesses to unions that are children of
   instrumented structs.  Furthermore, the line writes to the union,
   we should in fact report a write.  The shiny new
   is_component_ref_ancestor() function provides the necessary
   machinery, and this test case makes sure it all works.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test-harness-preamble.h"

/* Must define an expected[] array for test-harness.h to be
   meaningful. */
static struct expected_report expected[] = {
  SIMPLE_WRITE(foo, un, 2, 54),
  SIMPLE_READ(foo, un, 2, 56),
};

#include "test-harness.h"

struct foo {
  int field1;
  int field2;

  union {
    int a;
    unsigned int b;
  } un;
};

static struct foo foo;

noinstrument void __report_field_access(void *record_ptr, const char *record,
					const char *field, int field_index,
					int is_write, int is_marked,
					unsigned long bitmask, int *scratch,
					const char *filename, int lineno, int index)
{
  printf("%s reported for field %s (index: %d)\n",
	 (is_write ? "Write" : "Read"),
	 field,
	 field_index);

  check_report(record_ptr, record, field, field_index, is_write, is_marked,
	       bitmask, scratch, filename, lineno);
}

int main()
{
  expected_record_ptr = &foo;

  foo.un.a = 10;

  printf("Value in union: %u\n", foo.un.b);

  FINISH();
}
