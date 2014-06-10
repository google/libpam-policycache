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

#include "module.h"
#include "policy.h"
#include "storage.h"
#include "entry.h"
#include "util.h"

#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <syslog.h>


CacheModule *CacheModuleNew(const gchar *username, int pam_flags) {
  CacheModule *result = g_new0(CacheModule, 1);
  g_assert(username);
  result->action = CACHE_MODULE_UNKNOWN_ACTION;
  result->username = g_strdup(username);
  result->pam_flags = pam_flags;
  result->policy_path = g_strdup(DEFAULT_POLICY_PATH);
  result->storage_path = g_strdup(DEFAULT_STORAGE_PATH);
  return result;
}


void CacheModuleFree(CacheModule *self) {
  g_free(self->username);
  g_free(self->policy_path);
  g_free(self->storage_path);
  g_free(self);
}


gboolean CacheModuleAddArg(CacheModule *self, const gchar *arg,
                           GError **error) {
  if (g_str_equal(arg, "use_first_pass")) {
    self->use_first_pass = TRUE;
  } else if (g_str_equal(arg, "try_first_pass")) {
    self->try_first_pass = TRUE;
  } else if (g_str_equal(arg, "action=check")) {
    self->action = CACHE_MODULE_CHECK_ACTION;
  } else if (g_str_equal(arg, "action=update")) {
    self->action = CACHE_MODULE_UPDATE_ACTION;
  } else if (g_str_has_prefix(arg, "policy=")) {
    g_free(self->policy_path);
    self->policy_path = g_strdup(arg + strlen("policy="));
  } else if (g_str_has_prefix(arg, "storage=")) {
    g_free(self->storage_path);
    self->storage_path = g_strdup(arg + strlen("storage="));
  } else {
    g_set_error(
        error, CACHE_MODULE_ERROR, CACHE_MODULE_UNKNOWN_ARGUMENT_ERROR,
        "Unknown argument '%s'", arg);
    return FALSE;
  }

  return TRUE;
}


int CacheModuleDoAction(CacheModule *self, const gchar *password,
                        GError **error) {
  gchar **policy_paths = NULL;
  CachePolicy *policy = NULL;
  CacheStorage *storage = NULL;
  CacheEntry *entry = NULL;
  GError *tmp_error = NULL;
  int result = PAM_SYSTEM_ERR;

  policy_paths = CacheUtilGlob(self->policy_path);
  if (!policy_paths) {
    g_set_error(
        error, CACHE_MODULE_ERROR, CACHE_MODULE_NO_POLICY_ERROR,
        "Error looking for policy files using \"%s\"", self->policy_path);
  } else if (!policy_paths[0]) {
    g_set_error(
        error, CACHE_MODULE_ERROR, CACHE_MODULE_NO_POLICY_ERROR,
        "No policy files found using \"%s\"", self->policy_path);
    goto done;
  }

  g_assert(self->username);
  policy = CachePolicyNewForUser(self->username, policy_paths, error);
  if (!policy)
    goto done;

  storage = CacheStorageNew(self->storage_path);
  if (!storage)
    goto done;

  if (self->action == CACHE_MODULE_CHECK_ACTION) {
    entry = CacheStorageGetEntry(storage, self->username, error);
    if (!entry) {
      result = PAM_USER_UNKNOWN;
      goto done;
    }

    if (!CachePolicyCheckEntry(policy, entry, NULL, error)) {
      result = PAM_AUTHTOK_EXPIRED;
      goto done;
    }

    if (CacheEntryPasswordValidate(entry, password, error)) {
      result = PAM_SUCCESS;
    } else {
      result = PAM_AUTH_ERR;
    }
  } else if (self->action == CACHE_MODULE_UPDATE_ACTION) {
    entry = CacheEntryNew();
    if (!CacheEntryPasswordSet(entry, password, error)) {
      goto done;
    }
    result = PAM_IGNORE;
  } else {
    g_set_error(
        error, CACHE_MODULE_ERROR, CACHE_MODULE_NO_ACTION_ERROR,
        "No action argument given (action={check,update}).");
    goto done;
  }

  if (!CacheStoragePutEntry(storage, self->username, entry, &tmp_error)) {
    // TODO: Log error message.
    g_error_free(tmp_error);
  }

  if (result == PAM_SUCCESS && CachePolicyShouldRenew(policy, entry, NULL))
    result = PAM_NEW_AUTHTOK_REQD;

done:
  if (entry)
    CacheEntryUnref(entry);
  if (storage)
    CacheStorageUnref(storage);
  if (policy)
    CachePolicyUnref(policy);
  g_strfreev(policy_paths);
  return result;
}


PAM_EXTERN int
pam_sm_authenticate(
    pam_handle_t *pamh, int flags, int argc, const char **argv) {
  GError *error = NULL;
  const gchar *username = NULL;
  CacheModule *module = NULL;
  const gchar *password = NULL;
  int result = PAM_SYSTEM_ERR;

  if (pam_get_item(pamh, PAM_USER, (const void **) &username) != PAM_SUCCESS) {
    pam_syslog(pamh, LOG_WARNING, "Failed to get username");
    goto done;
  }

  if (!username) {
    // TODO: Prompt for the username.
    pam_syslog(pamh, LOG_WARNING, "No username available");
    goto done;
  }

  module = CacheModuleNew(username, flags);

  for (guint i = 0; i < argc; i++) {
    if (!CacheModuleAddArg(module, argv[i], &error)) {
      goto done;
    }
  }

  if (pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL) != PAM_SUCCESS ||
      !password ||
      !password[0]) {
    pam_syslog(pamh, LOG_WARNING, "No password available");
    result = PAM_CRED_INSUFFICIENT;
    goto done;
  }

  result = CacheModuleDoAction(module, password, &error);

done:
  if (error) {
    pam_syslog(
        pamh, LOG_WARNING,
        "Caught error for user '%s': %s", username, error->message);
    g_error_free(error);
    g_assert(result != PAM_SUCCESS);
  }
  pam_syslog(pamh, LOG_INFO, "Returning %s for user '%s'",
             pam_strerror(pamh, result), username);
  return result;
}


PAM_EXTERN int
pam_sm_setcred(
    pam_handle_t *pamh, int flags, int argc, const char **argv) {
  // TODO(vonhollen): Commit the new password to the cache here instead of in
  // pam_sm_authenticate so we know it succeeded.
  return PAM_IGNORE;
}


PAM_EXTERN int
pam_sm_acct_mgmt(
    pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return PAM_IGNORE;
}


PAM_EXTERN int
pam_sm_open_session(
    pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return PAM_IGNORE;
}


PAM_EXTERN int
pam_sm_close_session(
    pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return PAM_IGNORE;
}


PAM_EXTERN int
pam_sm_chauthtok(
    pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return PAM_IGNORE;
}


GQuark
_CacheModuleErrorQuark() {
  return g_quark_from_static_string("cache-module-error-quark");
}
