/* The file-test.c test is not specified in the config file, so Malloc
   Trace should ignore it completely.  If any of the hooks get called,
   something went wrong. */

#include <stdio.h>
#include <stdlib.h>

#define noinline __attribute__ ((noinline))
#define noinstrument __attribute__ ((hcos_noinstrument))

struct foo {
  int i;
  int j;
};

static struct foo allocation1;
static struct foo allocation2;

#define FAIL(...) do {				\
    fprintf(stderr, "FAIL: " __VA_ARGS__);	\
    exit(1);					\
  } while (1)

noinline void *kmalloc(unsigned int size)
{
  return &allocation1;
}

noinline void *kmap()
{
  return &allocation2;
}

noinline void kunmap(void *addr)
{
  printf("kunmap: %p\n", addr);
}

int main()
{
  struct foo *foo = kmalloc(sizeof(struct foo));
  printf("%p\n", foo);

  foo = kmap();
  printf("%p\n", foo);

  kunmap(foo);
  printf("%p\n", foo);

  /* If the hooks never get called, the test passes. */
  return 0;
}

void  __kmalloc_hook(void *addr, unsigned int size, const char *file, int lineno)
{
  FAIL("Function instrumented in uninstrumented file.\n");
}

void  __kmap_hook(void *addr, unsigned int size, const char *file, int lineno)
{
  FAIL("Function instrumented in uninstrumented file.\n");
}

void  __kunmap_hook(void *addr, unsigned int size, const char *file, int lineno)
{
  FAIL("Function instrumented in uninstrumented file.\n");
}
