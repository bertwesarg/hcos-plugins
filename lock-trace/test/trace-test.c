#include <stdio.h>
#include <stdlib.h>

#define noinline __attribute__ ((noinline))
#define noinstrument __attribute__ ((hcos_noinstrument))

/* The test sets the values just before it expects a hook to execute.
   The hook makes sure it gets exactly the values its expecting. */
static int expecting_hook = 0;  /* Do we expect the hook to get called at all? */
static void *expected_owner;
static void *expected_lock;
static int expected_success;

/* Keep track of how often hooks get called. */
static int num_lock_hooks = 0;
static int num_unlock_hooks = 0;

static int expected_lock_hooks = 3;
static int expected_unlock_hooks = 1;

/* These spin locks functions are _not_ a working spin lock
   implementation.  They are just here for testing. */
struct spin_lock {
  volatile int count;
};

void noinline spin_lock(struct spin_lock *lock)
{
  printf("Locking.\n");
  lock->count++;
}

void noinline spin_unlock(struct spin_lock *lock)
{
  printf("Unlocking.\n");
  lock->count--;
}

int noinline spin_trylock(struct spin_lock *lock)
{
  if (lock->count) {
    printf("Try lock failed.\n");
    return 0;
  }
  else {
    printf("Try lock succeeded.\n");
    lock->count++;
    return 1;
  }
}

/* Simulation of a struct whose locks we wish to track. */
struct inode {
  int foo;
  int bar;

  struct spin_lock lock;
};

void func()
{
  printf("Inside func.\n");
}

void (*function_pointer)() = func;

/* Test the noinstrument flag.  The locking in this function should
   not get instrumented. */
noinstrument noinline static void uninstrumented_locking(struct inode *inode)
{
  /* We do not expect the lock hook to get called! */
  expecting_hook = 0;

  printf("About to take spin lock without instrumentation.\n");
  spin_lock(&inode->lock);
  printf("Finished taking spin lock without instrumentation.\n");

  printf("About to release spin lock without instrumentation.\n");
  spin_unlock(&inode->lock);
  printf("Done releasing spin lock without instrumentation.\n");
}

int main()
{
  struct inode inode;
  inode.lock.count = 0;

  expecting_hook = 1;
  expected_owner = &inode;
  expected_lock = &inode.lock;
  expected_success = 1;

  printf("Starting main.  Inode: %p  Lock: %p\n", &inode, &inode.lock);

  printf("About to take spin lock.\n");
  spin_lock(&inode.lock);
  printf("Finished taking spin lock.\n");

  printf("About to release spin lock.\n");
  spin_unlock(&inode.lock);
  printf("Done releasing spin lock.\n");

  printf("About to try spin lock.\n");
  if (spin_trylock(&inode.lock)) {
    printf("Done trying spin lock.\n");

    expected_success = 0;
    printf("About to try spin lock second time.\n");
    if (spin_trylock(&inode.lock))
      printf("Done trying spin lock.\n");
    else
      printf("Done trying spin lock.\n");
  }

  /* An early version of Lock Trace would crash on attempts to call a
     function pointer. */
  printf("About to call function pointer.\n");
  function_pointer();
  printf("Done calling function pointer.\n");

  /* Test the noinstrument attribute. */
  uninstrumented_locking(&inode);

  if (num_lock_hooks < expected_lock_hooks) {
    fprintf(stderr, "FAIL: Too few lock hook invocations.\n");
  }
  else if (num_unlock_hooks < expected_unlock_hooks) {
    fprintf(stderr, "FAIL: Too few unlock hook invocations.\n");
  }
  else if (num_lock_hooks > expected_lock_hooks) {
    fprintf(stderr, "FAIL: Too many lock hook invocations.\n");
  }
  else if (num_unlock_hooks > expected_unlock_hooks) {
    fprintf(stderr, "FAIL: Too many unlock hook invocations.\n");
  }

  return 0;
}

static void check_expected_values(void *owner, void *lock, int success)
{
  if (!expecting_hook) {
    fprintf(stderr, "FAIL: Hook called at unexpected location\n");
    exit(1);
  }
  else if (expected_owner != owner) {
   fprintf(stderr, "FAIL: Hook called with wrong owner address\n");
   exit(1);
  }
  else if (expected_lock != lock) {
   fprintf(stderr, "FAIL: Hook called with wrong lock address\n");
   exit(1);
  }
  else if (expected_success != success) {
   fprintf(stderr, "FAIL: Hook called with wrong success value\n");
   exit(1);
  }
}

noinstrument void __lock_hook(struct inode *inode, struct spin_lock *lock,
			      int success, const char *struct_name,
			      const char *lock_name, const char *filename,
			      int lineno)
{
  printf("At %s:%d\n", filename, lineno);
  printf("Inside lock hook!  %s: %p, %s: %p (%s)\n",
	 struct_name, inode,
	 lock_name, lock,
	 success ? "Try succeeded" : "Try failed");

  check_expected_values(inode, lock, success);
  num_lock_hooks++;
}

noinstrument void __unlock_hook(struct inode *inode, struct spin_lock *lock,
				int success, const char *struct_name,
				const char *lock_name, const char *filename,
				int lineno)
{
  printf("At %s:%d\n", filename, lineno);
  printf("Inside unlock hook!  %s: %p, %s: %p (%s)\n",
	 struct_name, inode,
	 lock_name, lock,
	 success ? "Try succeeded" : "Try failed");

  check_expected_values(inode, lock, success);
  num_unlock_hooks++;
}
