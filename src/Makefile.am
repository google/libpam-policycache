AM_CFLAGS = $(GLIB_CFLAGS) -Wall -Werror \
	    -DG_LOG_DOMAIN="\"pamcache\""
AM_LDFLAGS = $(GLIB_LIBS) -lpam


# Common libraries for the tests, setuid helper, and the final PAM modules.
noinst_LTLIBRARIES = libcache.la libescalate.la

libcache_la_SOURCES = util.h util.c \
		      entry.h entry.c \
		      storage.h storage.c \
		      policy.h policy.c

libescalate_la_SOURCES = escalate_message.c escalate_message.h \
			 escalate_subprocess.c escalate_subprocess.h


# The final PAM modules.
securelibdir = $(libdir)/security
securelib_LTLIBRARIES = pam_policycache.la pam_escalate.la

pam_policycache_la_SOURCES = module.c module.h
pam_policycache_la_LIBADD = libcache.la
pam_policycache_la_LDFLAGS = -shared -module -avoid-version \
			     -export-symbols-regex 'pam_sm_*' \
			     $(AM_LDFLAGS)

pam_escalate_la_SOURCES = escalate_module.c escalate_module.h
pam_escalate_la_LIBADD = libescalate.la
pam_escalate_la_LDFLAGS = -shared -module -avoid-version \
			  -export-symbols-regex 'pam_sm_*' \
			  $(AM_LDFLAGS)


# The setuid helper for pam_escalate.
bin_PROGRAMS = pam-escalate-helper
pam_escalate_helper_SOURCES = escalate_helper.c escalate_helper.h
pam_escalate_helper_LDADD = libescalate.la


# Library and flags used for tests and to mock some libc/glib methods.
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

escalate_message_test_SOURCES = escalate_message_test.c
escalate_message_test_LDADD = libescalate.la
escalate_message_test_LDFLAGS = -no-install $(AM_LDFLAGS) $(MOCK_FLAGS)

check_PROGRAMS = util_test entry_test storage_test policy_test module_test \
		 escalate_message_test
TESTS = $(check_PROGRAMS)
