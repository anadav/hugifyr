AC_INIT([myproject], [1.0], [bug-report@example.com])
AC_CONFIG_SRCDIR([src/hugifyr.c])
AC_CONFIG_HEADERS([config.h])

# Check for C compiler (prefer GCC)
AC_PROG_CC
AS_IF([test "$GCC" != yes], [
    AC_MSG_WARN([GCC is preferred for this project])
])

# Function to suggest package names
suggest_package() {
    case $1 in
        elf) echo "libelf-dev (Debian/Ubuntu) or elfutils-libelf-devel (Fedora/CentOS)";;
        z) echo "zlib1g-dev (Debian/Ubuntu) or zlib-devel (Fedora/CentOS)";;
        zstd) echo "libzstd-dev (Debian/Ubuntu) or libzstd-devel (Fedora/CentOS)";;
        dwarf) echo "libdwarf-dev (Debian/Ubuntu) or libdwarf-devel (Fedora/CentOS)";;
    esac
}

# Check for required libraries
AC_CHECK_LIB([elf], [elf_begin], [], [
    AC_MSG_ERROR([libelf not found. Try installing $(suggest_package elf)])
])
AC_CHECK_LIB([z], [inflate], [], [
    AC_MSG_ERROR([zlib not found. Try installing $(suggest_package z)])
])
AC_CHECK_LIB([zstd], [ZSTD_compress], [], [
    AC_MSG_ERROR([libzstd not found. Try installing $(suggest_package zstd)])
])
AC_CHECK_LIB([dwarf], [dwarf_init], [], [
    AC_MSG_ERROR([libdwarf not found. Try installing $(suggest_package dwarf)])
])

# Check for required headers individually
AC_CHECK_HEADER([libelf.h], [], [
    AC_MSG_ERROR([libelf.h not found. Try installing $(suggest_package elf)])
])
AC_CHECK_HEADER([zlib.h], [], [
    AC_MSG_ERROR([zlib.h not found. Try installing $(suggest_package z)])
])
AC_CHECK_HEADER([zstd.h], [], [
    AC_MSG_ERROR([zstd.h not found. Try installing $(suggest_package zstd)])
])

# Check for libdwarf.h in /usr/include/libdwarf
AC_CHECK_HEADER([libdwarf/libdwarf.h],
    [LIBDWARF_CFLAGS="-I/usr/include/libdwarf"],
    [AC_MSG_ERROR([libdwarf.h not found in /usr/include/libdwarf. Try installing $(suggest_package dwarf)])])

# If libdwarf.h is not in the standard location, search for it
if test -z "$LIBDWARF_CFLAGS"; then
    AC_MSG_CHECKING([for libdwarf.h])
    for dir in /usr/include /usr/local/include /opt/include /usr/include/libdwarf /usr/local/include/libdwarf; do
        if test -f "$dir/libdwarf.h"; then
            LIBDWARF_CFLAGS="-I$dir"
            AC_MSG_RESULT([$dir])
            break
        fi
    done
    if test -z "$LIBDWARF_CFLAGS"; then
        AC_MSG_ERROR([libdwarf.h not found. Try installing $(suggest_package dwarf)])
    fi
fi

AC_SUBST([LIBDWARF_CFLAGS])

# Set up CFLAGS and LDFLAGS
CFLAGS="$CFLAGS -Wall -Wextra"
LDFLAGS="$LDFLAGS -lelf -lz -lzstd -ldwarf"

AC_CONFIG_FILES([Makefile])
AC_OUTPUT