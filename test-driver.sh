#!/bin/bash

# Read in arguments
INDEX=0
NEED_TESTCASE=1
PLUGIN_FLAGS=""
TEST_FILE=""

for arg in "$@"
do
    INDEX_MOD=$(( $INDEX % 2 ))

    if [ $INDEX -eq 0 ]
    then
	# First arg is the directory with the plug-in
	PLUGIN_DIR=$arg
    elif [ $INDEX -eq 1 ]
    then
	# Second arg is the name of the plug-in
	PLUGIN_NAME=$arg
	PLUGIN_FLAGS="-fplugin=${PLUGIN_DIR}/${PLUGIN_NAME}.so"
    elif [ $INDEX_MOD -eq 0 ]
    then
	# An even index means we are either looking at a plug-in arg
	# or the last argument (which will then be the test case
	# file).
	LAST_ARG=$arg
	NEED_TESTCASE=0
    else
	# An odd index means we are looking at a plug-in val
	PLUGIN_FLAGS="$PLUGIN_FLAGS -fplugin-arg-${PLUGIN_NAME}-${LAST_ARG}=${arg}"

	# Since $LAST_ARG was a plug-in arg and not the test case
	# name, we still need a test case name.
	NEED_TESTCASE=1
    fi

    INDEX=$(( $INDEX + 1 ))
done

TEST_FILE=$LAST_ARG

if [ "x$TEST_FILE" == "x" -o "x$PLUGIN_FLAGS" == "x" -o $NEED_TESTCASE -ne 0 ]
then
    echo "Usage: $0 plugin/dir pluginname [arg1 val1] [arg2 val2] ... test-case.c"
    exit 1
fi

if [ "x$CC" == "x" ]
then
    CC=gcc
fi

if [ "x$LIBEXEC_DIR" == "x" ]
then
    DRIVER_FLAGS=""
else
    DRIVER_FLAGS="-B$LIBEXEC_DIR"
fi

if [ "x$TEST_CFLAGS" == "x" ]
then
    # These plug-ins are mostly targeted for Linux kernel use, so we
    # test with kernel default cflags.
    TEST_CFLAGS='-Wall -Os'
else
    if [ "x$VERBOSE" != "x" ]
    then
	echo "Testing with non-default CFLAGS: $TEST_CFLAGS"
    fi
fi

# Compile the test file with the specified plug-in.
# DRIVER_FLAGS: Flags designed to go to the GCC driver itself (not cpp
# or cc1).  Specifically, -Bfoo/bar tells gcc the path to GCC binaries
# like cc1.
# PLUGIN_FLAGS: Flags that specify the plug-in to use and arguments to
# that plug-in.
# TEST_CLFAGS: The usual optimization/debugging flags.
if [ "x$VERBOSE" != "x" ]
then
    echo "Compiling with:"
    echo "$CC $DRIVER_FLAGS $PLUGIN_FLAGS $TEST_CFLAGS -o test-executable $TEST_FILE"
fi

$CC $DRIVER_FLAGS $PLUGIN_FLAGS $TEST_CFLAGS -o test-executable $TEST_FILE
if [ $? -ne 0 ]
then
    echo "$TEST_FILE: Failed to compile"
    rm test-executable
    exit 1
fi

# Execute the compiled test
if [ "x$VERBOSE" == "x" ]
then
    ./test-executable > /dev/null
else
    ./test-executable
fi

if [ $? -ne 0 ]
then
    echo "$TEST_FILE: Failed to execute"
    rm test-executable
    exit 1
fi

# Don't leave around old copies of the compiled test
rm test-executable
