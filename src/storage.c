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

#include "storage.h"

#include <string.h>


/**
 * CacheStorageNew:
 * @path: Directory where #CacheEntry instances are read/written.
 *
 * Returns: New instance of #CacheStorage.
 */
CacheStorage *CacheStorageNew(const char *path) {
  CacheStorage *self = g_new0(CacheStorage, 1);
  self->refcount = 1;
  self->path = g_strdup(path);
  g_assert(self->path);
  return self;
}


void CacheStorageRef(CacheStorage *self) {
  g_assert(self->refcount > 0);
  self->refcount++;
}


void CacheStorageUnref(CacheStorage *self) {
  g_assert(self->refcount > 0);
  self->refcount--;
  if (self->refcount)
    return;

  g_free(self->path);
  memset(self, 0, sizeof(*self));
  g_free(self);
}


static gchar *CacheStorageGetUserPath(CacheStorage *self, const gchar *username,
                                      GError **error) {
  g_assert(username);
  if (username[0] == '\0') {
      g_set_error(
          error, CACHE_STORAGE_ERROR, CACHE_STORAGE_USERNAME_ERROR,
          "Empty username is not supported");
      return NULL;
  }

  for (guint i = 0; username[i]; i++) {
    if (g_ascii_isalnum(username[i]))
      continue;

    switch (username[i]) {
      case '_':
      case '-':
        break;
      default:
        g_set_error(
            error, CACHE_STORAGE_ERROR, CACHE_STORAGE_USERNAME_ERROR,
            "Username '%s' contains unsupported characters",
            g_shell_quote(username));
        return NULL;
    }
  }

  return g_build_filename(self->path, username, NULL);
}


/**
 * CacheStorageGetEntry:
 * @self: #CacheStorage instance.
 * @username: User whose entry we want.
 * @error: (out)(allow-none): Error return location or #NULL.
 *
 * Returns: Instance of #CacheEntry or #NULL on error.
 */
CacheEntry *CacheStorageGetEntry(CacheStorage *self, const gchar *username,
                                  GError **error) {
  GError *tmp_error = NULL;
  gchar *path = NULL;
  gchar *contents = NULL;
  CacheEntry *result = NULL;

  path = CacheStorageGetUserPath(self, username, error);
  if (!path)
    goto done;

  if (!g_file_get_contents(path, &contents, NULL, &tmp_error)) {
    g_assert(tmp_error);
    g_set_error(error, CACHE_STORAGE_ERROR, CACHE_STORAGE_FILE_ERROR,
                "Failed to get cache entry for %s: %s", username,
                tmp_error->message);
    g_error_free(tmp_error);
    goto done;
  }

  result = CacheEntryUnserialize(contents, error);

done:
  g_free(contents);
  g_free(path);
  return result;
}


/**
 * CacheStoragePutEntry:
 * @self: #CacheStorage instance.
 * @username: User who owns the @entry.
 * @entry: #CacheEntry to write to disk.
 * @error: (out)(allow-none): Error return location or #NULL.
 *
 * Returns: #TRUE on success or #FALSE on error.
 */
gboolean CacheStoragePutEntry(CacheStorage *self, const gchar *username,
                              CacheEntry *entry, GError **error) {
  gchar *path = NULL;
  gchar *contents = NULL;
  gboolean result = FALSE;
  GError *tmp_error = NULL;

  path = CacheStorageGetUserPath(self, username, error);
  if (!path)
    goto done;

  contents = CacheEntrySerialize(entry);

  result = g_file_set_contents(path, contents, -1, &tmp_error);
  if (!result) {
    g_assert(tmp_error);
    g_set_error(error, CACHE_STORAGE_ERROR, CACHE_STORAGE_FILE_ERROR,
                "Failed to save cache entry for %s: %s", username,
                tmp_error->message);
    g_error_free(tmp_error);
  }

done:
  g_free(contents);
  g_free(path);
  return result;
}


GQuark
_CacheStorageErrorQuark() {
  return g_quark_from_string("cache-storage-error-quark");
}
