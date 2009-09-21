#include <stdio.h>
#include <stdlib.h>

/*
 * Test if Lock Trace can recognize a lock after a SSA rename.
 *
 * Code like this:
 * foo(struct inode *inode) {
 *   spin_lock(&inode->lock);
 *   ...
 *
 * gets broken down into GIMPLE that looks like this:
 * SSA_TEMP = &inode->lock
 * spin_lock(SSA_TEMP)
 *
 * Lock Trace needs to trace back to the statement that assigns to
 * SSA_TEMP to decide if the lock is one that deserves to be
 * instrumented.  This test case makes sure the plugin is doing that.
 */

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

static int expected_lock_hooks = 2;
static int expected_unlock_hooks = 2;

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

/* Simulation of a struct whose locks we wish to track. */
struct inode {
  int foo;
  int bar;

  struct spin_lock lock;
};

static void foo(struct inode *inode)
{
  expecting_hook = 1;
  expected_owner = inode;
  expected_lock = &inode->lock;
  expected_success = 1;

  printf("About to take spin lock.\n");
  spin_lock(&inode->lock);
  printf("Finished taking spin lock.\n");

  printf("About to release spin lock.\n");
  spin_unlock(&inode->lock);
  printf("Done releasing spin lock.\n");
}

/*
 * When we go back to find the statement that assigns an SSA_NAME's
 * value, we expect it to be a GIMPLE_ASSIGN.  In this case however
 * (when passing a function argument directly to spin_lock), there is
 * just a NOP statement.  Previously, the plugin did not check for
 * that condition and would crash.
 */
static void noinline bar(struct spin_lock *lock)
{
  expecting_hook = 0;

  printf("Take lock without owner. The hook function should not get called.\n");

  printf("About to take spin lock.\n");
  spin_lock(lock);
  printf("Finished taking spin lock.\n");

  printf("About to release spin lock.\n");
  spin_unlock(lock);
  printf("Done releasing spin lock.\n");  
}

int main()
{
  struct inode inode;
  inode.lock.count = 0;

  foo(&inode);
  foo(&inode);

  bar(&inode.lock);

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

void noinstrument __lock_hook(struct inode *inode, struct spin_lock *lock,
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

void noinstrument __unlock_hook(struct inode *inode, struct spin_lock *lock,
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
