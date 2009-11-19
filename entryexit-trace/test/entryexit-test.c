#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define noinstrument __attribute__((hcos_noinstrument))
#define noinline __attribute__((noinline))

#define FAIL(...) do {				\
    fprintf(stderr, "FAIL: " __VA_ARGS__);	\
    exit(1);					\
  } while (1)

struct expected_report {
  int is_entry;
  const char *func;
  int lineno;
};

#define ENTRY(FUNC, LINENO)			\
  {1, #FUNC, LINENO}				\

#define EXIT(FUNC, LINENO)			\
  {0, #FUNC, LINENO}				\

static struct expected_report expected[] = {
  ENTRY(sys_open, 76),
  EXIT(sys_open, 82),
  ENTRY(sys_open, 76),
  EXIT(sys_open, 82),
  ENTRY(sys_close, 90),
  EXIT(sys_close, 92),
  ENTRY(sys_close, 90),
  EXIT(sys_close, 92),
  ENTRY(sys_exit, 104),
  EXIT(sys_exit, 107),
};

static int num_reports = 0;
static int expected_size = sizeof(expected) / sizeof(struct expected_report);

noinstrument void check_report(int is_entry, const char *func, int lineno)
{
  if (num_reports >= expected_size)
    FAIL("Too many hook executions.\n");

  if (is_entry != expected[num_reports].is_entry)
    FAIL("Expected function %s but got function %s.\n",
	 expected[num_reports].is_entry ? "entry" : "exit",
	 is_entry ? "entry" : "exit");

  if (strcmp(func, expected[num_reports].func) != 0)
    FAIL("Expected function name %s but got %s.\n", expected[num_reports].func,
	 func);

  if (lineno != expected[num_reports].lineno)
    FAIL("Expected line number %d but got %d.\n", expected[num_reports].lineno,
	 lineno);

  num_reports++;
}

noinstrument void __entry_hook(const char *func, const char *filename,
			       int lineno)
{
  printf("Entry hook: %s at %s:%d\n", func, filename, lineno);
  check_report(1, func, lineno);
}

noinstrument void __exit_hook(const char *func, const char *filename,
			      int lineno)
{
  printf("Exit hook: %s at %s:%d\n", func, filename, lineno);
  check_report(0, func, lineno);
}

noinline int sys_open(int n)
{
  int i;

  printf("In sys_open()\n");

  for (i = 0 ; i < 100 ; i++) {
    if (i == n)
      return i;
  }

  return 0;
}

noinline int sys_close(int n)
{
  printf("In sys_close()\n");

  switch (n) {
  case 0:
    return 1;
  case 1:
    return 2;
  default:
    return 100;
  }
}

noinline void sys_exit()
{
  printf("In sys_exit()\n");
}

int main()
{
  sys_open(20);
  sys_open(120);

  sys_close(0);
  sys_close(1337);

  sys_exit();

  if (num_reports != expected_size)
    FAIL("Not enough hook executions (only %d of %d expected).", num_reports,
	 expected_size);

  return 0;
}
