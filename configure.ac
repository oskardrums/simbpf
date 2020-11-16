AC_PREREQ([2.69])
AC_INIT([simbpf], [0.1.0], [moskar.drummer@gmail.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
AC_CONFIG_SRCDIR([src/simbpf.c])
AC_CONFIG_HEADERS([include/config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_YACC
AC_PROG_LEX
AC_PROG_RANLIB
AM_PROG_AR


# Checks for libraries.
AC_CHECK_LIB([bpf], [bpf_load_program])

# Checks for header files.
AC_CHECK_HEADERS([stddef.h stdint.h stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memset strtoul])

AC_CONFIG_FILES([
 Makefile
 src/Makefile
 test/Makefile
])

AC_OUTPUT
