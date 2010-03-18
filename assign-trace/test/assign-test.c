#include <stdio.h>
#include <stdlib.h>

#define noinstrument __attribute__((hcos_noinstrument))

#define FAIL(...) do {				\
    fprintf(stderr, "FAIL: " __VA_ARGS__);	\
    exit(1);					\
  } while (1)

struct foo
{
  int a;
  int b;
};

volatile struct foo *ptr;
volatile struct bar
{
  struct foo *ptr;
} bar;
volatile struct foo *array[5];

static int num_hook_calls = 0;

void assign_global()
{
  struct foo foo;
  ptr = &foo;
}

void assign_struct()
{
  struct foo foo;
  bar.ptr = &foo;
}

void assign_array()
{
  struct foo foo;
  array[2] = &foo;
}

int main()
{
  assign_global();
  assign_struct();
  assign_array();

  if (num_hook_calls == 3)
    return 0;  /* Success */
  else if (num_hook_calls == 0)
    FAIL("No hook functions executed.\n");
  else
    FAIL("Number of hook executions did not match expected.\n");
}

noinstrument void __report_assignment(void **addr, const char *filename,
				      int lineno)
{
  void *expected;

  printf("Assignment reported: *%p = %p\n", addr, *addr);

  if (num_hook_calls == 0)
    expected = (void **)&ptr;
  else if (num_hook_calls == 1)
    expected = (void **)&bar.ptr;
  else if (num_hook_calls == 2)
    expected = (void **)&array[2];
  else
    FAIL("Too many assignments reported\n");

  if (addr != expected)
    FAIL("Reported address did not match expected. "
	 "Reported: %p, Expected: %p\n", addr, expected);

  num_hook_calls++;
}
