/* This test case tests almost exactly the same thing as share-test.c.
   The original solution for the bug that share-test.c tested was to
   use copy_node() for certain nodes that cannot be shared in the
   GIMPLE tree.

   However, copy node does not perform a deep copy, so illegal sharing
   could still occur.  This test case tickles that bug.  The solution
   is to use stabilize_ref() instead of copy_node(), which knows
   exactly which nodes need copying.

   Note on how this bug works:
   This test case references an inner struct by first taking its
   pointer and then dereferencing that pointer.  The compiler
   (intelligently) optimizes these two actions into one GIMPLE
   statement.  The condition of the if statement becomes:

     TEMP := (ptr->foo.a)

   This statement's GIMPLE tree is (in glorious TechniASCII)

       GIMPLE_MODIFY_STMT
          /          \
       (temp)    COMPONENT_REF
                 /           \
    ------------------------ (a)
   |       COMPONENT_REF    |
   |         /       \      |
   | INDIRECT_REF   (inner) |
   |      |                 |
   |    (ptr)               |
    ------------------------

   The box represents the part of the tree we want to reuse as an
   argument to the __report_*_access() function.

   Before using stabilize_ref() to fix this bug, Field Trace would
   correctly recognize that the COMPONENT_REF (in the box) cannot be
   shared and copy it instead.  It would not, however, copy the
   INDIRECT_REF, which it also should not share.

   Attempt this test case with -O2 and -Os.
*/

#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test-harness-preamble.h"

/* Must define an expected[] array for test-harness.h to be
   meaningful. */
static struct expected_report expected[] = {
  SIMPLE_READ(foo, a, 0, 88),
};

#include "test-harness.h"

struct foo {
  int a;
  int b;
};

struct struct_holder {
  int c;
  struct foo inner;
};

noinstrument void __report_field_access(void *record_ptr, const char *record,
					const char *field, int field_index,
					int is_write, int is_marked,
					unsigned long bitmask, int *scratch,
					const char *filename, int lineno)
{
  int i = *((int *)record_ptr);
  printf("Access reported with foo.a = %d\n", i);
  check_report(record_ptr, record, field, field_index, is_write, is_marked,
	       bitmask, scratch, filename, lineno);
}

int main() {
  struct struct_holder *ptr = malloc(sizeof(struct struct_holder));
  struct foo *foo;

  expected_record_ptr = &ptr->inner;

  foo = &ptr->inner;
  if (foo->a)
    printf("Test\n");

  return 0;
}
