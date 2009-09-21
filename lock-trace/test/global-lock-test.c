#include <stdio.h>
#include <stdlib.h>

#define noinline __attribute__ ((noinline))
#define noinstrument __attribute__ ((hcos_noinstrument))

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

/* Simulation of a global lock we are interested in tracking. */
struct spin_lock global_lock = { .count = 0 };

/* Simulation of a global lock we are _not_ interested in tracking. */
struct spin_lock irrelevant_lock = { .count = 0 };

/* The hook functions update these values to prove that they work. */
static int lock_acquisitions = 0;
static int failed_acquisitions = 0;
static int lock_releases = 0;

void noinstrument __lock_hook(void *record, struct spin_lock *lock,
			      int success, const char *struct_name,
			      const char *lock_name, const char *filename,
			      int lineno)
{
  printf("At %s:%d\n", filename, lineno);
  printf("Inside lock hook!  %s: %p, %s: %p (%s)\n",
	 struct_name, record,
	 lock_name, lock,
	 success ? "Try succeeded" : "Try failed");

  if (success)
    lock_acquisitions++;
  else
    failed_acquisitions++;
}

void noinstrument __unlock_hook(void *record, struct spin_lock *lock,
				int success, const char *struct_name,
				const char *lock_name, const char *filename,
				int lineno)
{
  printf("At %s:%d\n", filename, lineno);
  printf("Inside unlock hook!  %s: %p, %s: %p (%s)\n",
	 struct_name, record,
	 lock_name, lock,
	 success ? "Try succeeded" : "Try failed");

  /* Lock release should always succeed! */
  if (!success) {
    printf("FAIL: Failed lock release\n");
    exit(1);
  }

  lock_releases++;
}

int main()
{
  printf("About to take traced lock.\n");
  spin_lock(&global_lock);
  printf("Inside traced lock's critical section.\n");

  if (spin_trylock(&global_lock)) {
    printf("ERROR: spin_trylock test function is broken.\n");
    return 1;
  }
  else {
    printf("Correctly failed to try an already taken lock.\n");
  }

  spin_unlock(&global_lock);
  printf("Released traced lock.\n");

  printf("About to take untraced lock.\n");
  spin_lock(&irrelevant_lock);
  printf("Inside untraced lock's critical section.\n");
  spin_unlock(&irrelevant_lock);
  printf("Released untraced lock.\n");

  if (lock_acquisitions == 1 && failed_acquisitions == 1 && lock_releases == 1) {
    printf("PASS\n");
  }
  else {
    printf("FAIL: Lock hook functions did not execute the correct number of times.\n");
    exit (1);
  }

  return 0;
}
