AM_CFLAGS = $(GLIB_CFLAGS) -Wall -Werror \
	    -DG_LOG_DOMAIN="\"pamcache\""
AM_LDFLAGS = $(GLIB_LIBS) -lpam


# Common library for the tests and the final PAM module.
noinst_LTLIBRARIES = libcache.la
libcache_la_SOURCES = util.h util.c \
		      entry.h entry.c \
		      storage.h storage.c \
		      policy.h policy.c


# The final PAM module.
securelibdir = $(libdir)/security
securelib_LTLIBRARIES = pam_policycache.la
pam_policycache_la_SOURCES = module.c module.h
pam_policycache_la_LIBADD = libcache.la
pam_policycache_la_LDFLAGS = -shared -module -avoid-version \
			     -export-symbols-regex 'pam_sm_*' \
			     $(AM_LDFLAGS)


# Library and flags used to for tests and to mock some libc/glib methods.
MOCK_FLAGS = -Wl,--wrap,getpwnam \
	     -Wl,--wrap,getgrnam \
	     -Wl,--wrap,getgrgid \
	     -Wl,--wrap,getgrouplist \
	     -Wl,--wrap,g_file_get_contents \
	     -Wl,--wrap,g_file_set_contents \
	     -Wl,--wrap,g_date_time_new_now_utc

check_LTLIBRARIES = libtest.la
libtest_la_SOURCES = test.c test.h
libtest_la_LDFLAGS = $(MOCK_FLAGS)
libtest_la_CFLAGS = -DTESTDATA_DIR="\"$(top_srcdir)/testdata\"" \
		    $(AM_CFLAGS)


# Unit-tests with one executable per test-suite.
util_test_SOURCES = util_test.c
util_test_LDADD = libcache.la libtest.la
util_test_LDFLAGS = -no-install $(AM_LDFLAGS) $(MOCK_FLAGS)

entry_test_SOURCES = entry_test.c
entry_test_LDADD = libcache.la libtest.la
entry_test_LDFLAGS = -no-install $(AM_LDFLAGS) $(MOCK_FLAGS)

storage_test_SOURCES = storage_test.c
storage_test_LDADD = libcache.la libtest.la
storage_test_LDFLAGS = -no-install $(AM_LDFLAGS) $(MOCK_FLAGS)

policy_test_SOURCES = policy_test.c
policy_test_LDADD = libcache.la libtest.la
policy_test_LDFLAGS = -no-install $(AM_LDFLAGS) $(MOCK_FLAGS)

module_test_SOURCES = module.c module.h module_test.c
module_test_LDADD = libcache.la libtest.la
module_test_LDFLAGS = -no-install $(AM_LDFLAGS) $(MOCK_FLAGS)
module_test_CFLAGS = $(AM_CFLAGS)

check_PROGRAMS = util_test entry_test storage_test policy_test module_test
TESTS = $(check_PROGRAMS)
