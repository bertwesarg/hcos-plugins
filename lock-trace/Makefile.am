lib_LTLIBRARIES = liblock_trace.la
liblock_trace_la_SOURCES = lock-trace.c
liblock_trace_la_LDFLAGS = -version-info 1:0:0
#liblock_trace_la_CPPFLAGS = -DHAVE_CONFIG_H -DIN_GCC -I$(gcc_build)/gcc -I$(gcc_source)/gcc -I$(gcc_source)/include -I$(gcc_build)/intl -I$(gcc_source)/libcpp/include
liblock_trace_la_CPPFLAGS = -DHAVE_CONFIG_H -DIN_GCC -I$(gcc_includes)

SUBDIRS = test
