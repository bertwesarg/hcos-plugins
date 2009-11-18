#include <stdio.h>

#define noinstrument __attribute__((hcos_noinstrument))
#define noinline __attribute__((noinline))

noinstrument void __entry_hook(const char *func, const char *filename,
			       int lineno)
{
  printf("Entry hook: %s at %s:%d\n", func, filename, lineno);
}

noinstrument void __exit_hook(const char *func, const char *filename,
			      int lineno)
{
  printf("Exit hook: %s at %s:%d\n", func, filename, lineno);
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

  return 0;
}
