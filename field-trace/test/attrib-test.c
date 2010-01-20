/* It's important that Field Trace not add hooks to the hook function
 * itself or functions that it calls in order to avoid infinite
 * recursion.
 *
 * This test case exercises Field Trace "noinstrument" custom
 * attribute.  If Field Trace misses the attribute,
 * __report_field_access() will call itself and get stuck in an
 * infinite loop (until it runs out of stack space).
 *
 * This test case also tests that the "marked" attribute sets the
 * is_marked flags in access hooks.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test-harness-preamble.h"

/* Must define an expected[] array for test-harness.h to be
   meaningful. */
static struct expected_report expected[] = {
  SIMPLE_WRITE(foo, field1, 0, 75),
  SIMPLE_WRITE(foo, field2, 1, 76),
  SIMPLE_READ(foo, field2, 1, 60),  /* <- These execute in the reverse */
  SIMPLE_READ(foo, field1, 0, 60),  /* <- of the order you'd expect */
  MARKED_WRITE(foo, field1, 0, 82),
  MARKED_WRITE(foo, field2, 1, 83),
  SIMPLE_READ(foo, field2, 1, 60),
  SIMPLE_READ(foo, field1, 0, 60),
  MARKED_READ(foo, field2, 1, 65),
  MARKED_READ(foo, field1, 0, 65),
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
					const char *filename, int lineno,
					int index)
{
  int value = ((struct foo *)record_ptr)->field1;
  printf("At %s:%d\n", filename, lineno);
  printf("Call to __report_field_access: %d%s\n", value,
	 is_marked ? " (Marked)" : "");

  check_report(record_ptr, record, field, field_index, is_write, is_marked,
	       bitmask, scratch, filename, lineno);
}

__attribute__((noinline)) void read_foo(struct foo *foo)
{
  printf("Reading field: %d, %d\n", foo->field1, foo->field2);
}

__attribute__((noinline)) void read_marked(marked struct foo *foo)
{
  printf("Reading field: %d, %d\n", foo->field1, foo->field2);
}

int main()
{
  struct foo foo;
  marked struct foo marked_foo;

  expected_record_ptr = &foo;

  foo.field1 = 10;
  foo.field2 = 20;

  read_foo(&foo);

  expected_record_ptr = &marked_foo;

  marked_foo.field1 = 10;
  marked_foo.field2 = 20;

  read_foo(&marked_foo);

  /* Even though foo is not marked, the read_marked formal parameter
     is marked, so the two resulting accesses should both be counted
     as marked.  Marked is a lexical (i.e., not dynamic) property. */
  expected_record_ptr = &foo;
  read_marked(&foo);

  FINISH();
}
