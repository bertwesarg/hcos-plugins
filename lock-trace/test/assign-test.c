/* When the lock argument to a locking function is an SSA_NAME (which
   is almost always), Lock Trace wants to trace its origin using
   SSA_DEF_STMT.  Previously, we assumed that this def statement was
   always a GIMPLE_ASSIGN, but that turned out not to be the case.
   Make sure the plug-in does not crash if it turns out to be a
   GIMPLE_ASM or GIMPLE_PHI instead. */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#define noinline __attribute__ ((noinline))
#define noinstrument __attribute__ ((hcos_noinstrument))

struct spin_lock {
  int count;
};

struct spin_lock lock_array[] = { {0}, {0} };

noinline void spin_lock(struct spin_lock *lock)
{
  printf("Locking %p.\n", lock);
}

noinline void spin_unlock(struct spin_lock *lock)
{
  printf("Unlocking %p.\n", lock);
}

/* Thanks to some really out there code, it's possible for the
   SSA_DEF_STMT to be a GIMPLE_ASM. */
noinline void test_asm()
{
  uintptr_t ptr;
  struct spin_lock *lock;

  /* This is based on a weird compiler workaround in the kernel.  It
     accesses lock_array[1] in an intentionally obfuscated way so that
     the compiler can't make any assumptions about the pointer
     arithmetic. */
  lock = ({ptr = (uintptr_t)lock_array;
      __asm__ ("" : "=r"(ptr) : ""(lock_array));
      (struct spin_lock *)(ptr + sizeof(struct spin_lock)); });

  spin_lock(lock);
  spin_unlock(lock);
}

/* If you assign a lock variable in a conditional (rare but possible),
   then the SSA_DEF_STMT is a GIMPLE_PHI. */
noinline void test_phi(int i)
{
  struct spin_lock *lock;

  if (i == 0)
    lock = &lock_array[i];
  else
    lock = &lock_array[1];

  spin_lock(lock);
  spin_unlock(lock);
}

int main()
{
  test_asm();
  test_phi(1);

  return 0;
}

/* These should never be called. */
noinstrument void __lock_hook(void *owner, struct spin_lock *lock,
			      int success, const char *struct_name,
			      const char *lock_name, const char *filename,
			      int lineno)
{
  printf("FAIL: Inappropriate lock hook call.\n");
}

noinstrument void __unlock_hook(void *owner, struct spin_lock *lock,
				int success, const char *struct_name,
				const char *lock_name, const char *filename,
				int lineno)
{
  printf("FAIL: Inappropriate unlock hook call.\n");
}
