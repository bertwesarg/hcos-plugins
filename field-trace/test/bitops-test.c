/* Field Trace attempts to recognize bitwise operations, which read or
   write _part_ of a field using a bitmask.  There are four types of
   these operations:

   1. Set specific bits
     struct.field |= MASK
   2. Clear specific bits
     struct.field &= ~MASK
   3. Read specific bits
     if (struct.field & MASK) ...
   4. Read all _but_ specific bits (rare)
     if (~(struct.field | ~MASK)) ...

   In addition, each of the two write ops (set and clear) require a
   read to complete to remember values that the write should not
   modify.  Field Trace marks this kind of read as _inert_ by giving
   it an empty (0x0) bitmask.

   For flavor, this test case pulls example code out of the kernel,
   with a mock inode structure.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct foo {
  int bar;
  int baz;
  unsigned long i_state;
};

extern void test_bitmask();

/* A little bit of local color. */
#define I_DIRTY_SYNC		1
#define I_DIRTY_DATASYNC	2
#define I_DIRTY_PAGES		4
#define I_NEW			8
#define I_WILL_FREE		16
#define I_FREEING		32
#define I_CLEAR			64
#define __I_LOCK		7
#define I_LOCK			(1 << __I_LOCK)
#define __I_SYNC		8
#define I_SYNC			(1 << __I_SYNC)

#define I_DIRTY (I_DIRTY_SYNC | I_DIRTY_DATASYNC | I_DIRTY_PAGES)

#include "test-harness-preamble.h"

/* Must define an expected[] array for test-harness.h to be
   meaningful. */
static struct expected_report expected[] = {
  SIMPLE_WRITE(foo, i_state, 2, 87),
  BITMASK_READ(foo, i_state, 2, I_DIRTY, 90),
  INERT_READ(foo, i_state, 2, 94),
  BITMASK_WRITE(foo, i_state, 2, I_FREEING, 94),
  BITMASK_READ(foo, i_state, 2, (I_DIRTY|I_SYNC), 97),
  INERT_READ(foo, i_state, 2, 101),
  BITMASK_WRITE(foo, i_state, 2, (I_LOCK|I_NEW), 101),
  BITMASK_READ(foo, i_state, 2, I_FREEING, 107),
};

#include "test-harness.h"

struct foo my_inode;

noinstrument void __report_field_access(void *record_ptr, const char *record,
					const char *field, int field_index,
					int is_write, int is_marked,
					unsigned long bitmask, int *scratch,
					const char *filename, int lineno)
{
  printf("Struct %s with bitmask: 0x%08lx\n", (is_write ? "assign" : "access"),
	 bitmask);

  check_report(record_ptr, record, field, field_index, is_write, is_marked,
	       bitmask, scratch, filename, lineno);
}

void test_bitmask(struct foo *inode)
{
  volatile int bar;
  expected_record_ptr = inode;

  inode->i_state = I_CLEAR;

  /* Type 3: read specific bits. */
  if (inode->i_state & I_DIRTY)
    bar++;

  /* Type 1: set specific bits. */
  inode->i_state |= I_FREEING;

  /* Type 3: set specific bits. */
  if (inode->i_state & (I_DIRTY|I_SYNC))
    bar++;

  /* Type 2: clear specific bits. */
  inode->i_state &= ~(I_LOCK|I_NEW);

  /* Type 4: read all _but_ specific bits.
     I don't expect to see this case in actual code, but we should
     check it anyway: attempting to read all but a few bits using an |
     operation. */
  if (~(inode->i_state | (~I_FREEING)))
    bar++;
}

int main()
{
  test_bitmask(&my_inode);

  FINISH();
}
