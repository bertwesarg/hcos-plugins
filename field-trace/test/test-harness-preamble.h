#ifdef _TEST_HARNESS_PREAMBLE_H_
#error Include the test preamble only once
#endif

#define _TEST_HARNESS_PREAMBLE_H_

/* Included at the very beginning of a test, before defining the
   expected[] array.*/

struct expected_report {
  const char *record;
  const char *field;
  int field_index;
  int is_write;
  int is_marked;
  unsigned long bitmask;
  int lineno;
};

#define SIMPLE_READ(RECORD, FIELD, INDEX, LINENO)		\
  { #RECORD, #FIELD, INDEX, 0, 0, (unsigned long)-1, LINENO }

#define SIMPLE_WRITE(RECORD, FIELD, INDEX, LINENO)		\
  { #RECORD, #FIELD, INDEX, 1, 0, (unsigned long)-1, LINENO }

#define MARKED_READ(RECORD, FIELD, INDEX, LINENO)		\
  { #RECORD, #FIELD, INDEX, 0, 1, (unsigned long)-1, LINENO }

#define MARKED_WRITE(RECORD, FIELD, INDEX, LINENO)		\
  { #RECORD, #FIELD, INDEX, 1, 1, (unsigned long)-1, LINENO }
