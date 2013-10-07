# -*-sh-*-
AC_PREREQ(2.61)
AC_INIT(curve-keygen, `cat VERSION`)
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_MACRO_DIR(config)

AC_CONFIG_HEADER(libcsk/config.h)
AM_INIT_AUTOMAKE


ORIG_CFLAGS="${CFLAGS:-none}"

# Checks for programs
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_LIBTOOL
AC_PROG_SED
AC_PROG_AWK
AC_PROG_INSTALL

AC_ARG_WITH([libsodium],
            [AS_HELP_STRING([--with-libsodium],
                            [Specify libsodium prefix])],
            [search_libsodium="yes"],
            [])

if test "x$search_libsodium" = "xyes"; then
    if test -r "${with_libsodium}/include/sodium.h"; then
        CFLAGS="-I${with_libsodium}/include ${CFLAGS}"
        LDFLAGS="-L${with_libsodium}/lib ${LDFLAGS}"
    fi
fi



AC_ARG_WITH([libzmq],
            [AS_HELP_STRING([--with-libzmq],
                            [Specify libzmq prefix])],
            [search_libzmq="yes"],
            [])

if test "x$search_libzmq" = "xyes"; then
    if test -r "${with_libzmq}/include/zmq.h"; then
        CFLAGS="-I${with_libzmq}/include ${CFLAGS}"
        LDFLAGS="-L${with_libzmq}/lib ${LDFLAGS}"
    fi
fi


AC_ARG_WITH([libczmq],
            [AS_HELP_STRING([--with-libczmq],
                            [Specify libczmq prefix])],
            [search_libczmq="yes"],
            [])

if test "x$search_libczmq" = "xyes"; then
    if test -r "${with_libczmq}/include/czmq.h"; then
        CFLAGS="-I${with_libczmq}/include ${CFLAGS}"
        LDFLAGS="-L${with_libczmq}/lib ${LDFLAGS}"
    fi
fi

AC_CHECK_LIB(zmq, zmq_init, ,[AC_MSG_ERROR([cannot link with -lzmq, install libzmq.])])
AC_CHECK_LIB(sodium, sodium_init, , [AC_MSG_ERROR([cannot link with -lsodium, install libsodium.])])
AC_CHECK_LIB(czmq, zcert_new, ,[AC_MSG_ERROR([cannot link with -lczmq, install libczmq.])])


# Host speciffic checks
AC_CANONICAL_HOST

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(errno.h stdlib.h string.h unistd.h stdio.h getopt.h)

AC_TYPE_SIZE_T

# Checks for library functions.
AC_CHECK_FUNCS(perror memset memcpy malloc)

# Specify output files
AC_CONFIG_FILES([Makefile libcsk/Makefile src/Makefile man/Makefile])
AC_OUTPUT
