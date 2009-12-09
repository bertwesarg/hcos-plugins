#include <stdio.h>
#include <stdlib.h>

#define noinline __attribute__ ((noinline))
#define noinstrument __attribute__ ((hcos_noinstrument))

struct inode {
  int i;
  int j;
};

noinline struct inode *kmalloc(unsigned int size)
{
  struct inode *inode = malloc(sizeof(struct inode));
  return inode;
}

noinline struct inode *kmap()
{
  struct inode *inode = malloc(sizeof(struct inode));
  return inode;
}

noinline void kunmap(struct inode *inode)
{
  printf("Kunmap. %p\n",inode);
}

int main()
{

  struct inode *inode = kmalloc(8);
  printf("%p\n",inode);	
  inode = kmap();
  printf("%p\n",inode);	
  kunmap(inode);
  printf("%p\n",inode);	
  return 0;
}

void  __kmalloc_hook(void *addr, unsigned int size, const char *func, int lineno)
{
  printf("Inside kmalloc hook!  %p %d\n", addr, lineno);
}

void  __kmap_hook(void *addr, unsigned int size, const char *func, int lineno)
{
  printf("Inside kmap hook!  %p %d\n", addr, lineno);
}

void  __kunmap_hook(void *addr, unsigned int size, const char *func, int lineno)
{
  printf("Inside kunmap hook!  %p %d\n", addr, lineno);
}
