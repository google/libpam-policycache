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

#include "policy.h"
#include "util.h"

#include <netdb.h>


/**
 * CachePolicyNew:
 *
 * Returns: New #CachePolicy instance with default values.
 */
CachePolicy *CachePolicyNew() {
  CachePolicy *self = g_new0(CachePolicy, 1);
  self->refcount = 1;
  return self;
}


void CachePolicyRef(CachePolicy *self) {
  g_assert(self->refcount);
  self->refcount++;
}


void CachePolicyUnref(CachePolicy *self) {
  g_assert(self->refcount);
  self->refcount--;
  if (self->refcount)
    return;

  g_free(self);
}


/**
 * CachePolicyNewFromSection:
 * @key_file: Policy config file.
 * @section: Name of the section with the policy to load.
 * @error: (out)(allow-none): Return location for a #GError, or #NULL.
 *
 * Returns: New #CachePolicy with values parsed from the config file section, or
 * #NULL if there was any error while parsing values. Never returns a
 * half-parsed policy.
 */
CachePolicy *CachePolicyNewFromSection(GKeyFile *key_file,
                                       const gchar *section, GError **error) {
  CachePolicy *self = NULL;
  gchar **keys = NULL;

  keys = g_key_file_get_keys(key_file, section, NULL, error);
  if (!keys)
    return NULL;

  self = CachePolicyNew();

  for (guint i = 0; keys[i]; i++) {
    const gchar *key = keys[i];
    gchar *value = g_key_file_get_value(key_file, section, key, NULL);
    gboolean success = CachePolicySetValue(self, key, value, error);
    g_free(value);
    if (!success) {
      // Any error reading or parsing values is fatal.
      CachePolicyUnref(self);
      self = NULL;
      break;
    }
  }

  g_strfreev(keys);
  return self;
}


/**
 * CachePolicyMatchSection:
 * @username: Name of the user that the policy should apply to.
 * @groups: (array zero-terminated=1): List of group names the user belongs to.
 * @section: Config-file section name.
 *
 * Section names must be in one of the following formats:
 *   user:${username}
 *   group:${groupname}
 *   netgroup:${netgroup}
 *
 * Returns: #TRUE if @section defines a policy that applies to @username.
 */
static gboolean CachePolicyMatchSection(const gchar *username,
                                        const gchar **groups,
                                        const gchar *section) {
  gchar *section_type = NULL;
  gchar *section_name = NULL;
  gboolean result = FALSE;

  if (!CacheUtilSplitString(section, ":", &section_type, &section_name))
    return FALSE;

  if (g_str_equal(section_type, "user")) {
    result = g_str_equal(section_name, username);
  } else if (g_str_equal(section_type, "group")) {
    result = CacheUtilStringArrayContains(groups, section_name);
  } else if (g_str_equal(section_type, "netgroup")) {
    result = (innetgr(section_name, NULL, username, NULL)) ? TRUE : FALSE;
  }

  g_free(section_type);
  g_free(section_name);
  return result;
}


/**
 * CachePolicyNewForUser:
 * @username: Name of the user that the policy should apply to.
 * @paths: (array zero-terminated=1): List of policy config-file paths
 * containing the policies.
 * @error: (out)(allow-none): Return location for a #GError, or #NULL.
 *
 * Returns: New #CachePolicy with the values from the first policy section
 * that applies to @username, or #NULL if there was any error reading/parsing
 * the policy configs.
 */
CachePolicy *CachePolicyNewForUser(const gchar *username, const gchar **paths,
                                   GError **error) {
  gchar **groups = NULL;
  CachePolicy *self = NULL;
  gboolean found = FALSE;

  g_assert(paths);

  // Fetching group names is expensive, so only do it once.
  groups = CacheUtilGetGroupsForUser(username);
  if (!groups) {
    g_set_error(error, CACHE_POLICY_ERROR, CACHE_POLICY_UNKNOWN_USER_ERROR,
                "User '%s' was not found in the password/group database",
                username);
    return NULL;
  }

  for (guint i = 0; !found && paths[i]; i++) {
    const gchar *path = paths[i];
    GKeyFile *key_file = NULL;
    gchar **sections = NULL;

    if (!g_file_test(path, G_FILE_TEST_IS_REGULAR))
      continue;  // Policy file not found, which is OK.

    key_file = g_key_file_new();
    if (!g_key_file_load_from_file(key_file, path, G_KEY_FILE_NONE, error))
      break;  // Couldn't parse policy, which is fatal.

    sections = g_key_file_get_groups(key_file, NULL);
    for (guint j = 0; !found && sections[j]; j++) {
      const gchar *section = sections[j];
      if (CachePolicyMatchSection(username, (const gchar **) groups, section)) {
        // Found a suitable section, so set 'found' which ends both loops.
        found = TRUE;

        // Any errors parsing the section are fatal, so 'self' may be NULL.
        self = CachePolicyNewFromSection(key_file, section, error);
        if (!self) {
          g_prefix_error(error,
                         "Error parsing section '%s' in '%s': ", section, path);
        }
      }
    }

    g_strfreev(sections);
    g_key_file_free(key_file);
  }

  if (!found && error && !*error) {
    // No section was found, but no error was set, so return a generic
    // not-found error.
    g_set_error(error, CACHE_POLICY_ERROR, CACHE_POLICY_UNKNOWN_USER_ERROR,
                "No policy found for user '%s'", username);
  }

  g_strfreev(groups);
  return self;
}


static gboolean CachePolicySetCount(const gchar *value, guint *result) {
  gchar *endptr = NULL;
  gint64 tmp_result = g_ascii_strtoll(value, &endptr, 10);
  if (tmp_result < 0 || value == endptr || *endptr != '\0') {
    return FALSE;
  } else {
    *result = tmp_result;
    return TRUE;
  }
}


static gboolean CachePolicySetDuration(const gchar *value, GTimeSpan *result) {
  GTimeSpan tmp_result = 0;
  if (CacheUtilTimespanFromString(value, &tmp_result) && tmp_result >= 0) {
    *result = tmp_result;
    return TRUE;
  } else {
    return FALSE;
  }
}


/**
 * CachePolicySetValue:
 * @self: Policy to modify.
 * @key: Attribute name to modify.
 * @value: String value for the attribute.
 * @error: (out)(allow-none): Return location for a #GError, or #NULL.
 *
 * Sets the value of a policy attribute using a key and value string.
 *
 * Supported attributes are "tries" (positive int), "refresh" (duration),
 * "renew" (duration), and "expire" (duration).
 *
 * Duration attributes accept values like "5d" for five days or "1w" for one
 * week.
 *
 * All values are zero/null by default, which indicates that the value should
 * not be used.
 *
 * Returns: #TRUE if value was parsed and @self was updated.
 */
gboolean CachePolicySetValue(CachePolicy *self, const gchar *key,
                             const char *value, GError **error) {
  gboolean result = FALSE;
  g_assert(key);
  g_assert(value);

  if (g_str_equal(key, "tries")) {
    result = CachePolicySetCount(value, &self->max_tries);
  } else if (g_str_equal(key, "refresh")) {
    result = CachePolicySetDuration(value, &self->refresh_before);
  } else if (g_str_equal(key, "renew")) {
    result = CachePolicySetDuration(value, &self->renew_after);
  } else if (g_str_equal(key, "expire")) {
    result = CachePolicySetDuration(value, &self->expire_after);
  } else {
    g_set_error(error, CACHE_POLICY_ERROR, CACHE_POLICY_UNKNOWN_KEY_ERROR,
                "Unknown key '%s'", key);
    return FALSE;
  }

  if (!result) {
    g_set_error(error, CACHE_POLICY_ERROR, CACHE_POLICY_INVALID_VALUE_ERROR,
                "Invalid value '%s' for key '%s'", value, key);
  }

  return result;
}


/**
 * CachePolicyCheckEntry:
 * @self: Policy used to check @entry's validity.
 * @entry: Cache entry that could be used to validate a password.
 * @now: (allow-none): The time when @entry is being checked, or #NULL for
 * the current time.
 * @error: (out)(allow-none): Return location for a #GError, or #NULL.
 *
 * Returns: #TRUE if @entry may be used to validate a password, or #FALSE if
 * it's expired.
 */
gboolean CachePolicyCheckEntry(CachePolicy *self, CacheEntry *entry,
                               GDateTime *now, GError **error) {
  gboolean result = FALSE;

  g_assert(self);
  g_assert(entry);

  if (now) {
    g_date_time_ref(now);
  } else {
    now = g_date_time_new_now_utc();
  }

  if (self->max_tries && entry->tries > self->max_tries) {
    g_set_error(error, CACHE_POLICY_ERROR,
                CACHE_POLICY_MAX_TRIES_EXCEEDED_ERROR,
                "Cache entry used too many times without success");
    goto done;
  }

  if (self->refresh_before &&
      !CacheUtilCheckDuration(now, self->refresh_before, entry->last_used)) {
    g_set_error(error, CACHE_POLICY_ERROR, CACHE_POLICY_ENTRY_EXPIRED_ERROR,
                "Cache entry expired because it wasn't used");
    goto done;
  }

  if (self->expire_after &&
      !CacheUtilCheckDuration(now, self->expire_after, entry->last_verified)) {
    g_set_error(error, CACHE_POLICY_ERROR, CACHE_POLICY_ENTRY_EXPIRED_ERROR,
                "Cache entry expired because it was never renewed");
    goto done;
  }

  result = TRUE;

done:
  g_date_time_unref(now);
  return result;
}


/**
 * CachePolicyShouldRenew:
 * @self: Policy used to check @entry's validity.
 * @entry: Cache entry that can be used to validate a password. Should have been
 * checked with CachePolicyCheckEntry() already.
 * @now: (allow-none): The time when @entry is being checked, or #NULL for
 * the current time.
 *
 * Returns: #TRUE if the password should be tried against another auth
 * mechanism, even if CacheEntryPasswordValidate() succeeded. Prevents @entry
 * from expiring when validation against other mechanisms hasn't been needed.
 */
gboolean CachePolicyShouldRenew(CachePolicy *self, CacheEntry *entry,
                                GDateTime *now) {
  gboolean result = FALSE;

  g_assert(self);
  g_assert(entry);

  if (now) {
    g_date_time_ref(now);
  } else {
    now = g_date_time_new_now_utc();
  }

  if (self->renew_after &&
      !CacheUtilCheckDuration(now, self->renew_after, entry->last_verified)) {
    result = TRUE;
  }

  g_date_time_unref(now);
  return result;
}


GQuark
_CachePolicyErrorQuark() {
  return g_quark_from_static_string("cache-policy-error-quark");
}
