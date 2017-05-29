/**
 * Copyright 2016 Google Inc. All rights reserved.
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
#include "util.h"
#include "module.h"
#include "import.h"
#include "entry.h"
#include <string.h>
#include <stdio.h>


/**
 * CacheImport:
 * @shadow_path: Path to shadow file.
 * @shadow_hash: Hashed password. 
 * @storage_path: Path to store policy cache entry.
 * @username: Username to create cache entry for.
 * @error: Errors.
 *
 * Returns: #True if CacheEntry was created or #False on failure.
 */

gboolean CacheImport(const char *shadow_path, const char *storage_path, const char *username, GError **error) {
  gboolean result = FALSE;
  CacheStorage *storage = NULL;
  CacheEntry *entry = NULL;
 
  if (!shadow_path) {
    shadow_path = "/etc/shadow";
  }
  
  if (!storage_path) {
    storage_path = DEFAULT_STORAGE_PATH;
  }

  // Get user's hashed password if present.
  GBytes* shadow_hash = CacheUtilReadShadowFile(shadow_path, username, error);
  if (!shadow_hash) {
    goto done;
  }

  //GBytes* shadow_hash = CacheUtilReadShadowFile(shadow_path, username, error);

  // Create a new Cache Entry.
  entry = CacheEntryNew();

  // Set the newly created entry hash using the /etc/shadow hash.
  CacheEntryHashSet(entry, CACHE_ENTRY_ALGORITHM_CRYPT, shadow_hash);

  storage = CacheStorageNew(storage_path);

  result = CacheStoragePutEntry(storage, username, entry, error);

done:
  if (!shadow_hash) {
    g_free(shadow_hash);
  } 
  g_bytes_unref(shadow_hash); 

  if (entry) { 
    CacheEntryUnref(entry);
  }
  if (storage) {
    CacheStorageUnref(storage);
  }
  return result;
}

#ifndef CACHE_IMPORT_TESTING
int main(int argc, char *argv[]) {
  GError *error = NULL;
  GOptionContext *context = NULL;
 
  static gchar* shadow_path = NULL;
  static gchar* storage_path = NULL;
  static GOptionEntry entries[] = 
    {
        { "shadow-path", 'p', 0, G_OPTION_ARG_STRING, &shadow_path, "Path to search for hashed passwords."},
        { "storage-path", 's', 0, G_OPTION_ARG_STRING, &storage_path, "Path to storage policy cache."},
	{ NULL }
    };

  context = g_option_context_new("- import shadow hash module");
  g_option_context_add_main_entries(context, entries, NULL);
  if (!g_option_context_parse(context, &argc, &argv, &error)) {
    goto done;
  }
 
  if (argc > 1) {
    char *user = argv[1];
    if (user != NULL) { 
      CacheImport(shadow_path, storage_path, user, &error);    
    }  
  }
      
  done:
    if (error) {
      g_printerr("Failure: %s\n", error->message);
      g_error_free(error);
      return 1;
    }
    return 0;
}
#endif

GQuark _CacheImportErrorQuark() {
  return g_quark_from_string("cache-import-error-quark");
}
