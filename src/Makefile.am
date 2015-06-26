AM_CFLAGS = $(GLIB_CFLAGS) -Wall -Werror \
	    -DG_LOG_DOMAIN="\"pamcache\"" \
	    -fPIC -fstack-protector-all -D_FORTIFY_SOURCE=2 \
	    -Wl,-z,relro,-z,now -Wformat -Wformat-security
AM_LDFLAGS = $(GLIB_LIBS) -lpam -Wa,--noexecstack


# Common libraries for the tests, setuid helper, and the final PAM modules.
noinst_LTLIBRARIES = libcache.la libescalate.la

libcache_la_SOURCES = util.h util.c \
		      entry.h entry.c \
		      storage.h storage.c \
		      policy.h policy.c

libescalate_la_SOURCES = escalate_message.c escalate_message.h \
			 escalate_subprocess.c escalate_subprocess.h \
			 escalate_util.c escalate_util.h


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
pam_escalate_helper_LDFLAGS = $(AM_LDFLAGS) -pie

install-exec-hook:
	chmod u+s $(DESTDIR)$(bindir)/pam-escalate-helper


# Library and flags used for tests and to mock some libc/glib methods.
check_LTLIBRARIES = libtest.la libescalatetest.la

MOCK_FLAGS = -Wl,--wrap,getpwnam \
	     -Wl,--wrap,getgrnam \
	     -Wl,--wrap,getgrgid \
	     -Wl,--wrap,getgrouplist \
	     -Wl,--wrap,g_file_get_contents \
	     -Wl,--wrap,g_file_set_contents \
	     -Wl,--wrap,g_date_time_new_now_utc

libtest_la_SOURCES = test.c test.h util.c util.h
libtest_la_LDFLAGS = $(MOCK_FLAGS)
libtest_la_CFLAGS = -DTESTDATA_DIR="\"$(top_srcdir)/testdata\"" \
		    $(AM_CFLAGS)

ESCALATE_MOCK_FLAGS = -Wl,--wrap,pam_start \
		      -Wl,--wrap,pam_end \
		      -Wl,--wrap,pam_get_item \
		      -Wl,--wrap,pam_set_item \
		      -Wl,--wrap,pam_get_user \
		      -Wl,--wrap,pam_getenv \
		      -Wl,--wrap,pam_putenv \
		      -Wl,--wrap,pam_getenvlist \
		      -Wl,--wrap,pam_syslog \
		      -Wl,--wrap,pam_authenticate \
		      -Wl,--wrap,pam_setcred \
		      -Wl,--wrap,g_spawn_async_with_pipes \
		      -Wl,--wrap,getuid \
		      -Wl,--wrap,geteuid \
		      -Wl,--wrap,getgid \
		      -Wl,--wrap,getegid

libescalatetest_la_SOURCES = escalate_test.c escalate_test.h
libescalatetest_la_LDFLAGS = $(ESCALATE_MOCK_FLAGS)


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
escalate_message_test_LDFLAGS = -no-install $(AM_LDFLAGS)

escalate_subprocess_test_SOURCES = escalate_subprocess_test.c
escalate_subprocess_test_LDADD = libescalate.la
escalate_subprocess_test_LDFLAGS = -no-install $(AM_LDFLAGS)

escalate_module_test_SOURCES = escalate_module.c escalate_module.h \
			       escalate_module_test.c
escalate_module_test_LDADD = libescalate.la libescalatetest.la libtest.la
escalate_module_test_LDFLAGS = -no-install $(AM_LDFLAGS) $(MOCK_FLAGS) \
			       $(ESCALATE_MOCK_FLAGS)
escalate_module_test_CFLAGS = $(AM_CFLAGS)

escalate_helper_test_SOURCES = escalate_helper.c escalate_helper.h \
			       escalate_helper_test.c
escalate_helper_test_LDADD = libescalate.la libescalatetest.la libtest.la
escalate_helper_test_LDFLAGS = -no-install $(AM_LDFLAGS) $(MOCK_FLAGS) \
			       $(ESCALATE_MOCK_FLAGS)
escalate_helper_test_CFLAGS = -DESCALATE_HELPER_TESTING=1 $(AM_CFLAGS)

check_PROGRAMS = util_test entry_test storage_test policy_test module_test \
		 escalate_message_test escalate_subprocess_test \
		 escalate_helper_test escalate_module_test
TESTS = $(check_PROGRAMS)

noinst_PROGRAMS = pam_test_tool
