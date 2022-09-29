# Autoconf requirements
# Force autoconf to be at least this version number:
AC_PREREQ([2.69])
# Initialize, but use more options.  Note parameters brackets and whitespace.
AC_INIT([swagmac], [1.0], [w7og@yahoo.com])
# Safety check - list a source file that wouldn't be in other directories:
AC_CONFIG_SRCDIR([src/swagmac.c])

# Put autotools auxiliary files in a subdir, so they don't clutter top dir:
AC_CONFIG_AUX_DIR([build-aux])

AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_TARGET
# AC_CANONICAL_HOST is needed to access the 'host_os' variable
AC_CANONICAL_HOST

build_linux=no
build_windows=no
build_freebsd=no

# Detect the target system
case "${host_os}" in
    linux*)
        build_linux=yes
        ;;
    cygwin*|mingw*)
        build_windows=yes
        ;;
    freebsd*)
        build_freebsd=yes
        ;;
    *)
        AC_MSG_ERROR(["OS $host_os is not supported"])
        ;;
esac

# Pass the conditionals to automake
AM_CONDITIONAL([LINUX], [test "$build_linux" = "yes"])
AM_CONDITIONAL([WINDOWS], [test "$build_windows" = "yes"])
AM_CONDITIONAL([FREEBSD], [test "$build_freebsd" = "yes"])

# see GNU autoconf archive = perdefined macros
if test "$build_linux" = "yes"; then
AX_GENERATE_CHANGELOG
fi

# Enable "automake" to simplify creating makefiles:
AM_INIT_AUTOMAKE([1.11 subdir-objects -Wall -Werror])

# Look for a C compiler:
AC_PROG_CC([gcc cl cc])
AC_PROG_CXX
AM_PROG_AS
AC_PROG_INSTALL
AC_PROG_CPP
AC_PROG_AWK
AC_PROG_MKDIR_P
AM_PROG_CC_C_O
AC_C_BIGENDIAN

swagmac_version_1=`echo $PACKAGE_VERSION | cut -d . -f 1`
swagmac_version_2=`echo $PACKAGE_VERSION | cut -d . -f 2`
swagmac_version_3=`echo $PACKAGE_VERSION | cut -d . -f 3`
swagmac_version=$swagmac_version_1.$swagmac_version_2.$swagmac_version_3
AC_DEFINE_UNQUOTED(SWAGMAC_VERSION,  "$swagmac_version",  [ SWAGMAC version string.  ])
AC_DEFINE_UNQUOTED(SWAGMAC_VERSION_1, $swagmac_version_1, [ SWAGMAC version level 1. ])
AC_DEFINE_UNQUOTED(SWAGMAC_VERSION_2, $swagmac_version_2, [ SWAGMAC version level 2. ])
AC_DEFINE_UNQUOTED(SWAGMAC_VERSION_3, $swagmac_version_3, [ SWAGMAC version level 3. ])
AC_SUBST(SWAGMAC_VERSION, $swagmac_version)

# Checks for libraries.
AC_CHECK_LIB([xml2], [xmlFreeDoc])
AC_CHECK_LIB([telnet], [telnet_init])
AC_CHECK_LIB([mongoc-1.0], [mongoc_init])
AC_CHECK_LIB([bson-1.0], [bson_init])

# Checks for header files.
AC_INCLUDES_DEFAULT
AC_CHECK_HEADERS([malloc.h ctype.h termios.h sys/socket.h arpa/inet.h netinet/in.h arpa/inet.h netdb.h poll.h errno.h termios.h libtelnet.h])
AC_CHECK_HEADERS([libxml2/libxml/xmlmemory.h libxml2/libxml/parser.h libbson-1.0/bson.h libmongoc-1.0/mongoc.h])

# Checks for typedefs, structures, macros, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_C_RESTRICT
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t])

# Checks for compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_DEFINE(_GNU_SOURCE, 1, [ Define to enable GNU extensions in glibc ])
AC_HEADER_STDC

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_FUNC_ALLOCA

# Options

AC_ARG_ENABLE(debug,
  AC_HELP_STRING(
    [--enable-debug],
    [enable development-time debugging @<:@default=disabled@:>@]),
  [ swagmac_debug="$enableval" ],
  [ swagmac_debug="no" ])
if test "$swagmac_debug" = "yes"; then
  AM_CONDITIONAL(DEBUG, true)
  AC_DEFINE(DEBUG, 1,
    [ Define if you want swagmac to print debug messages to stdout. ])
  CFLAGS="$CFLAGS -g"
else
  AM_CONDITIONAL(DEBUG, false)
  AC_DEFINE(NDEBUG, 1, [ Define if you want to disable debug assertions. ])
  CFLAGS="-O2"
  CXXFLAGS="-O2"
fi

AC_ARG_ENABLE(windoze,
  AC_HELP_STRING(
    [--enable-windoze],
    [enable Windows code @<:@default=disabled@:>@]),
  [ swagmac_windoze="$enableval" ],
  [ swagmac_windoze="no" ])
if test "$swagmac_windoze" = "yes"; then
  AM_CONDITIONAL(WINDOZE, true)
  AC_DEFINE(WINDOZE, 1,
    [ Define if you wish to generate code for the Microsoft Windows gui. ])
else
  AM_CONDITIONAL(WINDOZE, false)
fi

AC_SYS_LARGEFILE

AM_PROG_AR
LT_INIT([disable-shared])
AC_SUBST([LIBTOOL_DEPS])


# Output files
# Put configuration results here, so we can easily #include them:
AC_CONFIG_HEADERS([config.h])
# other files to creat
AC_CONFIG_FILES([
Makefile
m4/Makefile
build-aux/Makefile
])

MY_CPPFLAGS=" -I/usr/include/libxml2 -I/usr/include/libbson-1.0 -I/usr/include/libmongoc-1.0"
AC_SUBST(MY_CPPFLAGS)

# Do final output.
AC_OUTPUT


# Print configuration summary

cat <<EOF


Configuration summary
=====================

swagmac is now configured as follows:

* Compilation environment

  CC       = $CC
  CFLAGS   = $CFLAGS
  CPP      = $CPP
  CPPFLAGS = $CPPFLAGS
  LD       = $LD
  LDFLAGS  = $LDFLAGS
  LIBS     = $LIBS


* swagmac options

  Development-time debugging:		$swagmac_debug
  Compile for Windows gui:		$swagmac_windoze


EOF

