#ifndef _TEST_HARNESS_H_
#define _TEST_HARNESS_H_

/* This test harness has common functions and macros that every test
   case should have.  Include this _after_ the definition of the
   expected[] array. */

#define noinstrument __attribute__((hcos_noinstrument))
#define marked __attribute__((hcos_marked))

#define FAIL(...) do {				\
    fprintf(stderr, "FAIL: " __VA_ARGS__);	\
    exit(1);					\
  } while (1)

noinstrument void check_ptr(const char *name, void *reported, void *expected)
{
  if (reported != expected)
    FAIL("Reported %s did not match expected. Reported: %p, Expected: %p\n",
	 name, reported, expected);
}

noinstrument void check_string(const char *name, const char *reported,
			       const char *expected)
{
  if (strcmp(reported, expected) != 0)
    FAIL("Reported %s did not match expected. Reported: %s, Expected: %s\n",
	 name, reported, expected);
}

noinstrument void check_int(const char *name, int reported, int expected)
{
  if (reported != expected)
    FAIL("Reported %s did not match expected. Reported: %d, Expected: %d\n",
	 name, reported, expected);
}

noinstrument void check_bool(const char *name, int reported, int expected)
{
  if ((reported && !expected) || (expected && !reported))
    FAIL("Reported %s did not match expected. Reported: %s, Expected: %s\n",
	 name, reported ? "true" : "false", expected ? "true" : "false");
}

noinstrument void check_bitmask(const char *name, unsigned int reported,
				unsigned int expected)
{
  if (reported != expected)
    FAIL("Reported %s did not match expected. Reported: 0x%x, Expected: 0x%x\n",
	 name, reported, expected);
}

/* Usually a test will involve just one record_ptr.  The test's main
   function should set that pointer here. */
static void *expected_record_ptr = NULL;

static int num_reports = 0;
static int expected_size = sizeof(expected) / sizeof(expected[0]);

noinstrument void check_report(void *record_ptr, const char *record,
			       const char *field, int field_index, int is_write,
			       int is_marked, unsigned long bitmask,
			       int *scratch, const char *filename, int lineno)
{
  if (num_reports >= expected_size)
    FAIL("Too many field accesses reported (expected %d)\n", expected_size);

  check_ptr("record_ptr", record_ptr, expected_record_ptr);
  check_string("record", record, expected[num_reports].record);
  check_string("field", field, expected[num_reports].field);
  check_int("field_index", field_index, expected[num_reports].field_index);
  check_bool("is_write", is_write, expected[num_reports].is_write);
  check_bool("is_marked", (is_marked & 0x1), expected[num_reports].is_marked);
  check_bitmask("bitmask", bitmask, expected[num_reports].bitmask);
  check_int("lineno", lineno, expected[num_reports].lineno);

  num_reports++;
}

#define FINISH() do {						\
    if (num_reports == expected_size)				\
      return 0;  /* Success */					\
    else if (num_reports == 0)					\
      FAIL("No hook functions executed.\n");			\
    else							\
      FAIL("Number of hook executions did not match expected."	\
	   "  Reported: %d, Expected: %d\n",			\
	   num_reports, expected_size);				\
} while(1)

#endif
