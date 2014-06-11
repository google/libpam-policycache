/**
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "entry.h"
#include "module.h"
#include "policy.h"
#include "storage.h"
#include "test.h"

#include <security/pam_modules.h>
#include <security/pam_ext.h>


#define AssertActionSuccess(module, password, expected_pam_result) { \
  GError *error = NULL; \
  int pam_result = CacheModuleDoAction(module, password, &error); \
  g_assert_no_error(error); \
  g_assert_cmpint(pam_result, ==, expected_pam_result); }


#define AssertActionError(module, password, expected_pam_result, \
                          expected_error_quark, expected_error_code) { \
  GError *error = NULL; \
  int pam_result = CacheModuleDoAction(module, password, &error); \
  g_assert_error(error, expected_error_quark, expected_error_code); \
  g_assert_cmpint(pam_result, ==, expected_pam_result); \
  g_error_free(error); }


static CacheModule *CreateTestModule(const gchar *username,
                                     int flags, const gchar *args) {
  GError *error = NULL;
  CacheModule *module = CacheModuleNew(username, flags);
  gchar *policy_path = CacheTestGetDataPath("policy1.conf");
  gchar *policy_value = g_shell_quote(policy_path);
  gchar *final_args = g_strdup_printf("policy=%s storage=/mockfs %s",
                                      policy_value, args);
  gchar **argv = NULL;
  gint argc = 0;
  g_shell_parse_argv(final_args, &argc, &argv, &error);
  g_assert_no_error(error);

  for (guint i = 0; argv[i]; i++) {
    g_assert(CacheModuleAddArg(module, argv[i], &error));
    g_assert_no_error(error);
  }

  g_free(policy_path);
  g_free(policy_value);
  g_free(final_args);
  g_strfreev(argv);
  return module;
}


static void TestMissAddAndMatch() {
  CacheModule *check_module = CreateTestModule("janedoe", 0, "action=check");
  CacheModule *update_module = CreateTestModule("janedoe", 0, "action=update");

  CacheTestInit();
  CacheTestInitFiles();

  AssertActionError(check_module, "supersecret", PAM_USER_UNKNOWN,
                    CACHE_STORAGE_ERROR, CACHE_STORAGE_FILE_ERROR);

  AssertActionSuccess(update_module, "supersecret", PAM_IGNORE);
  AssertActionSuccess(check_module, "supersecret", PAM_SUCCESS);

  CacheModuleFree(check_module);
  CacheModuleFree(update_module);
}


static void TestRefreshPolicy() {
  CacheModule *check_module = CreateTestModule("janedoe", 0, "action=check");
  CacheModule *update_module = CreateTestModule("janedoe", 0, "action=update");

  CacheTestInit();
  CacheTestInitFiles();

  AssertActionSuccess(update_module, "supersecret", PAM_IGNORE);

  // Password stays active if it's used every two days.
  CacheTestAddMockTime(G_TIME_SPAN_DAY * 2);
  AssertActionSuccess(check_module, "supersecret", PAM_SUCCESS);

  CacheTestAddMockTime(G_TIME_SPAN_DAY * 2);
  AssertActionSuccess(check_module, "supersecret", PAM_SUCCESS);

  // But it expires if it hasn't been used in four days.
  CacheTestAddMockTime(G_TIME_SPAN_DAY * 4);
  AssertActionError(check_module, "supersecret", PAM_AUTHTOK_EXPIRED,
                    CACHE_POLICY_ERROR, CACHE_POLICY_ENTRY_EXPIRED_ERROR);

  CacheModuleFree(check_module);
  CacheModuleFree(update_module);
}


static void TestRenewPolicy() {
  CacheModule *check_module = CreateTestModule("janedoe", 0, "action=check");
  CacheModule *update_module = CreateTestModule("janedoe", 0, "action=update");

  CacheTestInit();
  CacheTestInitFiles();

  AssertActionSuccess(update_module, "supersecret", PAM_IGNORE);

  // Using the cache doesn't affect the renew timer, only updates do.
  for (guint i = 0; i < 14; i++) {
    CacheTestAddMockTime(G_TIME_SPAN_DAY);
    AssertActionSuccess(check_module, "supersecret", PAM_SUCCESS);
  }

  // After two weeks, the password works but tries to renew with another module.
  CacheTestAddMockTime(G_TIME_SPAN_DAY);
  AssertActionSuccess(check_module, "supersecret", PAM_NEW_AUTHTOK_REQD);

  CacheModuleFree(check_module);
  CacheModuleFree(update_module);
}


static void TestExpirePolicy() {
  CacheModule *check_module = CreateTestModule("janedoe", 0, "action=check");
  CacheModule *update_module = CreateTestModule("janedoe", 0, "action=update");

  CacheTestInit();
  CacheTestInitFiles();

  AssertActionSuccess(update_module, "supersecret", PAM_IGNORE);

  // Using the cache doesn't affect the expire timer, only updates do.
  for (guint i = 0; i < 14; i++) {
    CacheTestAddMockTime(G_TIME_SPAN_DAY);
    AssertActionSuccess(check_module, "supersecret", PAM_SUCCESS);
  }
  for (guint i = 0; i < 7; i++) {
    CacheTestAddMockTime(G_TIME_SPAN_DAY);
    AssertActionSuccess(check_module, "supersecret", PAM_NEW_AUTHTOK_REQD);
  }

  // Even though the password was used continuously, after three weeks it
  // expires.
  CacheTestAddMockTime(G_TIME_SPAN_DAY);
  AssertActionError(check_module, "supersecret", PAM_AUTHTOK_EXPIRED,
                    CACHE_POLICY_ERROR, CACHE_POLICY_ENTRY_EXPIRED_ERROR);

  // Unless it's updated by another module.
  AssertActionSuccess(update_module, "supersecret", PAM_IGNORE);
  AssertActionSuccess(check_module, "supersecret", PAM_SUCCESS);

  CacheModuleFree(check_module);
  CacheModuleFree(update_module);
}


static void TestBadPassword() {
  CacheModule *check_module = CreateTestModule("janedoe", 0, "action=check");
  CacheModule *update_module = CreateTestModule("janedoe", 0, "action=update");

  CacheTestInit();
  CacheTestInitFiles();

  AssertActionSuccess(update_module, "supersecret", PAM_IGNORE);

  // First five tries are normal failures, and the sixth locks the entry because
  // the policy includes "tries=5".
  for (guint i = 0; i < 6; i++) {
    AssertActionError(check_module, "wrongsecret", PAM_AUTH_ERR,
                      CACHE_ENTRY_ERROR, CACHE_ENTRY_PASSWORD_ERROR);
  }

  // Future tries fail, even when correct, because the password was tried too
  // many times.
  AssertActionError(check_module, "supersecret", PAM_AUTHTOK_EXPIRED,
                    CACHE_POLICY_ERROR, CACHE_POLICY_MAX_TRIES_EXCEEDED_ERROR);

  CacheModuleFree(check_module);
  CacheModuleFree(update_module);
}


static void TestRepeatArgument() {
  CacheModule *module = CacheModuleNew("janedoe", 0);
  GError *error = NULL;
  gboolean result = FALSE;

  result = CacheModuleAddArg(module, "use_first_pass", &error);
  g_assert_no_error(error);
  g_assert(result);

  result = CacheModuleAddArg(module, "use_first_pass", &error);
  g_assert_error(error, CACHE_MODULE_ERROR, CACHE_MODULE_REPEAT_ARGUMENT_ERROR);
  g_assert(!result);

  g_error_free(error);
  CacheModuleFree(module);
}


static void TestInvalidActionArgument() {
  CacheModule *module = CacheModuleNew("janedoe", 0);
  GError *error = NULL;
  gboolean result = CacheModuleAddArg(module, "action=lol", &error);
  g_assert_error(error, CACHE_MODULE_ERROR,
                 CACHE_MODULE_INVALID_ARGUMENT_ERROR);
  g_assert(!result);
  g_error_free(error);
  CacheModuleFree(module);
}


static void TestUnknownArgument() {
  CacheModule *module = CacheModuleNew("janedoe", 0);
  GError *error = NULL;
  gboolean result = CacheModuleAddArg(module, "nope", &error);
  g_assert_error(error, CACHE_MODULE_ERROR,
                 CACHE_MODULE_UNKNOWN_ARGUMENT_ERROR);
  g_assert(!result);
  g_error_free(error);
  CacheModuleFree(module);
}


int main(int argc, char **argv) {
  CacheTestInit();
  CacheTestInitUsersAndGroups();
  g_test_init(&argc, &argv, NULL);
  g_test_add_func("/module_test/TestMissAddAndMatch", TestMissAddAndMatch);
  g_test_add_func("/module_test/TestRefreshPolicy", TestRefreshPolicy);
  g_test_add_func("/module_test/TestRenewPolicy", TestRenewPolicy);
  g_test_add_func("/module_test/TestExpirePolicy", TestExpirePolicy);
  g_test_add_func("/module_test/TestBadPassword", TestBadPassword);
  g_test_add_func("/module_test/TestRepeatArgument", TestRepeatArgument);
  g_test_add_func("/module_test/TestInvalidActionArgument",
                  TestInvalidActionArgument);
  g_test_add_func("/module_test/TestUnknownArgument", TestUnknownArgument);
  return g_test_run();
}
