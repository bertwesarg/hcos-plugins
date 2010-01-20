/* Transparent unions are a non-standard feature of C, but the Linux
   kernel uses them, so Field Trace supports them.  The idea is that a
   struct can have an unnamed union.  Syntactically, members of the
   unnamed union get accessed just like members of the struct, but
   they share the same memory like a regular union.

   Furthermore, you can nest these unions as much as you want, as is
   done here.  I have no idea why that would be useful. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test-harness-preamble.h"

/* Must define an expected[] array for test-harness.h to be
   meaningful. */
static struct expected_report expected[] = {
  SIMPLE_WRITE(foo, a, 0, 77),
  SIMPLE_WRITE(foo, b, 1, 78),
  SIMPLE_WRITE(foo, c, 2, 79),
  SIMPLE_WRITE(foo, d, 3, 80),
  SIMPLE_WRITE(foo, e, 4, 81),
  SIMPLE_WRITE(foo, f, 5, 82),
  SIMPLE_READ(foo, a, 0, 64),
  SIMPLE_READ(foo, b, 1, 65),
  SIMPLE_READ(foo, c, 2, 66),
  SIMPLE_READ(foo, d, 3, 67),
  SIMPLE_READ(foo, e, 4, 68),
  SIMPLE_READ(foo, f, 5, 69),
};

#include "test-harness.h"

struct foo {
  int a;
  union {
    int b;
    float c;

    /* Yes, this really is allowed. */
    union {
      void *d;
      char e;
    };
  };
  int f;
};

noinstrument void __report_field_access(void *record_ptr, const char *record,
					const char *field, int field_index,
					int is_write, int is_marked,
					unsigned long bitmask, int *scratch,
					const char *filename, int lineno, int index)
{
  printf("%s reported, field %s (index %d)\n", (is_write ? "Write" : "Read"), field, field_index);

  check_report(record_ptr, record, field, field_index, is_write, is_marked,
	       bitmask, scratch, filename, lineno);
}

void print_foo(struct foo *foo)
{
  printf("%d\n", foo->a);
  printf("%d\n", foo->b);
  printf("%f\n", foo->c);
  printf("%p\n", foo->d);
  printf("%c\n", foo->e);
  printf("%d\n", foo->f);
}

int main()
{
  struct foo foo;
  expected_record_ptr = &foo;

  foo.a = 1;
  foo.b = 2;
  foo.c = 3.0;
  foo.d = NULL;
  foo.e = 'a';
  foo.f = 4;

  print_foo(&foo);

  FINISH();
}
