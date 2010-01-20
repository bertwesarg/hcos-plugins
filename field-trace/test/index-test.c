/* The index parameter is suppoed to be unique for each access site
   (i.e., each place a hook is added).  Test that the hook indexes get
   assigned the way we want them.

   Since we're only testing the index (and this is the only test case
   that tests index), we don't bother with the full test harness. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define noinstrument __attribute__((hcos_noinstrument))

static int expected[] = {
  0, 1, 2, 3, 0, 1, 2, 3,
};

static int expected_size = sizeof(expected) / sizeof(int);
static int num_reports = 0;

struct foo {
  int bar;
  int baz;
};

noinstrument void __report_field_access(void *record_ptr, const char *record,
					const char *field, int field_index,
					int is_write, int is_marked,
					unsigned long bitmask, int *scratch,
					const char *filename, int lineno,
					int index)
{
  int expected_index;
  printf("Struct %s with index: %d\n", (is_write ? "assign" : "access"), index);

  expected_index = expected[num_reports];
  if (index != expected_index) {
    fprintf(stderr, "FAIL: Reported index did not match expected."
	    " Reported: %d, Expected %d\n", index, expected_index);
    exit(1);
  }

  num_reports++;
}

static __attribute__((noinline)) void access_struct(volatile struct foo *foo)
{
  int i;

  for (i = 0 ; i < 2 ; i++) {
    foo->bar = 1;
    foo->baz = 2;

    foo->bar = foo->baz;
  }
}

noinstrument int main()
{
  struct foo foo;

  access_struct(&foo);

  if (num_reports == expected_size) {
    return 0;  /* Success */
  }
  else if (num_reports == 0) {
    fprintf(stderr, "Fail: No hook functions executed.\n");
    return 1;
  }
  else {
    fprintf(stderr, "Fail Number of hook executions did not match expected."
	 "  Reported: %d, Expected: %d\n",
	 num_reports, expected_size);
    return 1;
  }
}
