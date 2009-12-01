#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define noinstrument __attribute__((hcos_noinstrument))
#define noinline __attribute__((noinline))

static int entry_calls = 0;
static int exit_calls = 0;

noinstrument void __entry_hook(const char *func, const char *filename,
			       int lineno)
{
  printf("Entry hook: %s at %s:%d\n", func, filename, lineno);
  entry_calls++;
}

noinstrument void __exit_hook(const char *func, const char *filename,
			      int lineno)
{
  printf("Exit hook: %s at %s:%d\n", func, filename, lineno);
  exit_calls++;
}

noinline void sys_open(int n)
{
loop:
  if (n > 0) {
    printf("In goto loop...\n");
    n--;
    goto loop;
  }
}

int main()
{
  sys_open(2);

  if (entry_calls == 1 && exit_calls == 1) {
    return 0;
  }
  else {
    fprintf(stderr, "FAIL: Incorrect number of calls to hook functions.\n");
    return 1;
  }
}
