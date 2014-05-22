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

#include "test.h"
#include "util.h"

#include <string.h>

static GDateTime *mock_time = NULL;
static GPtrArray *mock_users = NULL;
static GPtrArray *mock_groups = NULL;
static GHashTable *mock_files = NULL;

gboolean __real_g_file_get_contents(const gchar *filename, gchar **contents,
                                    gsize *length, GError **error);
gboolean __real_g_file_set_contents(const gchar *filename, gchar *contents,
                                    gssize length, GError **error);


static void FreePasswd(struct passwd *value) {
  g_free(value->pw_name);
}


static void FreeGroup(struct group *value) {
  g_free(value->gr_name);
  g_strfreev(value->gr_mem);
}


void CacheTestInit() {
  CacheTestSetMockTime(NULL);
}


void CacheTestInitUsersAndGroups() {
  if (mock_users)
    g_ptr_array_free(mock_users, TRUE);
  if (mock_groups)
    g_ptr_array_free(mock_users, TRUE);

  mock_users = g_ptr_array_new_with_free_func((GDestroyNotify) FreePasswd);
  mock_groups = g_ptr_array_new_with_free_func((GDestroyNotify) FreeGroup);

  CacheTestAddMockUser(100, "janedoe");
  CacheTestAddMockUser(101, "johndoe");
  CacheTestAddMockUser(102, "popularuser");
  CacheTestAddMockGroup(100, "janedoe", "janedoe", NULL);
  CacheTestAddMockGroup(101, "johndoe", "johndoe", NULL);
  CacheTestAddMockGroup(102, "popularuser", "popularuser", NULL);
  CacheTestAddMockGroup(200, "noone", NULL);
  CacheTestAddMockGroup(201, "everyone", "janedoe", "johndoe", "popularuser",
                        NULL);
  for (guint i = 0; i < 256; i++) {
    gchar *name = g_strdup_printf("othergroup%d", i);
    CacheTestAddMockGroup(1000 + i, name, "popularuser", NULL);
    g_free(name);
  }
}


void CacheTestInitFiles() {
  if (mock_files)
    g_hash_table_destroy(mock_files);
  mock_files = g_hash_table_new_full(g_str_hash, g_str_equal,
                                     (GDestroyNotify) g_free,
                                     (GDestroyNotify) g_bytes_unref);
}


gchar *CacheTestGetDataPath(const gchar *filename) {
  return g_build_filename(TESTDATA_DIR, filename, NULL);
}


GBytes *CacheTestGetDataBytes(const gchar *filename, GError **error) {
  gchar *path = CacheTestGetDataPath(filename);
  gchar *contents = NULL;
  gsize length = 0;
  GBytes *result = NULL;

  if (g_file_get_contents(filename, &contents, &length, error)) {
    result = g_bytes_new_take((gpointer) contents, length);
  }

  g_free(path);
  return result;
}


void CacheTestSetMockTime(GDateTime *value) {
  if (mock_time) {
    g_date_time_unref(mock_time);
  }

  if (value) {
    mock_time = value;
    g_date_time_ref(mock_time);
  } else {
    mock_time = g_date_time_new_utc(2000, 1, 1, 0, 0, 0);
  }
}


void CacheTestAddMockTime(GTimeSpan value) {
  g_assert(mock_time);
  CacheTestSetMockTime(g_date_time_add(mock_time, value));
}


GDateTime *__wrap_g_date_time_new_now_utc() {
  g_assert(mock_time);
  g_date_time_ref(mock_time);
  return mock_time;
}


void CacheTestAddMockUser(uid_t uid, const gchar *name) {
  struct passwd *value = g_new0(struct passwd, 1);
  value->pw_uid = uid;
  value->pw_gid = uid;
  value->pw_name = g_strdup(name);
  g_ptr_array_add(mock_users, (gpointer) value);
}


void CacheTestAddMockGroup(gid_t gid, const gchar *name, ...) {
  struct group *value = g_new0(struct group, 1);
  va_list ap;
  const gchar *member = NULL;
  GPtrArray *members = g_ptr_array_new();

  va_start(ap, name);
  do {
    member = va_arg(ap, const gchar *);
    g_ptr_array_add(members, (gpointer) g_strdup(member));
  } while (member);
  va_end(ap);

  value->gr_gid = gid;
  value->gr_name = g_strdup(name);
  value->gr_mem = (char **) g_ptr_array_free(members, FALSE);
  g_ptr_array_add(mock_groups, (gpointer) value);
}


struct passwd *__wrap_getpwnam(const char *name) {
  for (guint i = 0; i < mock_users->len; i++) {
    struct passwd *value = (struct passwd *) g_ptr_array_index(mock_users, i);
    if (g_str_equal(value->pw_name, name)) {
      return value;
    }
  }
  return NULL;
}


struct group *__wrap_getgrnam(const char *name) {
  for (guint i = 0; i < mock_groups->len; i++) {
    struct group *value = (struct group *) g_ptr_array_index(mock_groups, i);
    if (g_str_equal(value->gr_name, name)) {
      return value;
    }
  }
  return NULL;
}


struct group *__wrap_getgrgid(gid_t gid) {
  for (guint i = 0; i < mock_groups->len; i++) {
    struct group *value = (struct group *) g_ptr_array_index(mock_groups, i);
    if (value->gr_gid == gid) {
      return value;
    }
  }
  return NULL;
}


int __wrap_getgrouplist(const char *user, gid_t group, gid_t *groups,
                        int *ngroups) {
  guint group_count = 1;

  if (*ngroups > 0) {
    groups[0] = group;
  }

  for (guint i = 0; i < mock_groups->len; i++) {
    struct group *value = (struct group *) g_ptr_array_index(mock_groups, i);
    if (value->gr_gid == group)
      continue;

    if (CacheUtilStringArrayContains((const gchar **) value->gr_mem, user)) {
      if (*ngroups > group_count) {
        groups[group_count] = value->gr_gid;
      }
      group_count += 1;
    }
  }

  if (*ngroups >= group_count) {
    *ngroups = group_count;
    return group_count;
  } else {
    *ngroups = group_count;
    return -1;
  }
}


gboolean __wrap_g_file_set_contents(const gchar *filename, gchar *contents,
                                    gssize length, GError **unused_error) {
  gchar *key = g_strdup(filename);
  GByteArray *value = g_byte_array_new();

  g_assert(g_str_has_prefix(key, "/mock"));

  if (length == -1)
    length = strlen(contents);
  g_assert(length >= 0);

  g_byte_array_append(value, (guint8 *) contents, length);
  g_byte_array_append(value, (guint8 *) "", 1);
  g_hash_table_replace(mock_files, key, g_byte_array_free_to_bytes(value));
  return TRUE;
}


gboolean __wrap_g_file_get_contents(const gchar *filename, gchar **contents,
                                    gsize *length, GError **error) {
  GBytes *value = NULL;
  gsize value_length = 0;

  if (!g_str_has_prefix(filename, "/mock"))
    return __real_g_file_get_contents(filename, contents, length, error);

  value = (GBytes *) g_hash_table_lookup(mock_files, filename);

  if (!value) {
    g_set_error(error, G_FILE_ERROR, G_FILE_ERROR_EXIST,
                "Mock file \"%s\" doesn't exist", filename);
    return FALSE;
  }

  g_assert(contents);
  g_bytes_ref(value);
  *contents = g_bytes_unref_to_data(value, &value_length);
  if (length)
    *length = value_length - 1;
  return TRUE;
}
