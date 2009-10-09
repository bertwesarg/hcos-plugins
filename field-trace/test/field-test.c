/* A simple test that exercises Hook insertions for field acceses. */

#include <stdio.h>

#define noinstrument __attribute__((hcos_noinstrument))
#define mark_access __attribute__((hcos_marked))

struct inode {
  int field1;
  int field2;
};

struct simple_t {
  int x;
  int y;
};

struct box_t {
  struct simple_t ul;
  struct simple_t lr;
};

noinstrument void __report_inode_access(struct inode *inode, const char *record,
					const char *field, int field_index,
					int is_write, int is_marked,
					unsigned long bitmask, int *scratch,
					const char *filename, int lineno) {
  int *field_val = (int *)inode;
  printf("At %s:%d\n", filename, lineno);
  printf("Field access: %s[Index: %d] >>>> %s (Value: %d) [%s]\n",
	 record,
	 field_index,
	 field,
	 *field_val,
	 is_write ? "write" : "read");
}

int main() {
  volatile struct inode inode;
  volatile struct inode *ptr;
  volatile struct inode **ptr2;

  printf("Yay!\n");

  inode.field2 = 10;
  inode.field2 = 20;

  /* This should get reported as a read then a write. */
  inode.field1++;

  ptr = &inode;
  ptr->field1 = 10;
  (*ptr).field1 = 20;

  ptr2 = &ptr;
  (*ptr2)->field1 = 10;
  (*ptr2)->field1 = 20;

  return 0;
}
