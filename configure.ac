AC_PREREQ([2.68])
AC_INIT([libpam-policycache], [0.11], [https://github.com/google/libpam-policycache])
AC_CONFIG_AUX_DIR([autotools])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AM_SILENT_RULES([yes])

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_STDC
AM_PROG_CC_C_O

# Checks for libraries.
AM_PROG_AR
LT_INIT
PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.32.4])
AC_CHECK_LIB([scrypt], [libscrypt_scrypt], [], [AC_MSG_ERROR([libscrypt not found])])
AC_CHECK_LIB([crypt], [crypt], [], [AC_MSG_ERROR([libcrypt not found])])
AC_CHECK_LIB([pam], [pam_start], [], [AC_MSG_ERROR([libpam not found])])

# Checks for header files.
AC_CHECK_HEADERS(
    [stdint.h stdlib.h string.h crypt.h],
    [], [AC_MSG_ERROR([missing system headers])])
AC_CHECK_HEADERS(
    [security/pam_appl.h security/pam_client.h security/pam_ext.h],
    [], [AC_MSG_ERROR([missing libpam headers])])
AC_CHECK_HEADERS(
    [libscrypt.h],
    [], [AC_MSG_ERROR([missing libscrypt headers])])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset])

AC_CONFIG_FILES([Makefile
                 testdata/Makefile
                 src/Makefile])
AC_OUTPUT
