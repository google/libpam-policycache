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
#include "module.h"
#include "entry.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <shadow.h>

/**
 * CreateEntryFromShadowHash:
 * @username: Username containing the shadow hash.
 * @sdhash: User's hashed shadow password.
 */
gboolean CreateEntryFromShadowHash(const char *username, char *sdhash) {
  // Create a new Cache Entry.
  CacheEntry *entry = CacheEntryNew();
  GBytes* gbytes = g_bytes_new(sdhash, strlen(sdhash));
  // Set the newly created entry hash using the /etc/shadow hash.
  CacheEntryHashSet(entry, CACHE_ENTRY_ALGORITHM_CRYPT, gbytes, NULL);
  g_bytes_unref(gbytes);
  GError *error = NULL;
  CacheStorage *storage = CacheStorageNew(DEFAULT_STORAGE_PATH);
  if (!CacheStoragePutEntry(storage, username, entry, &error))
      goto done;

  done:
    if (error) {
      fprintf(stderr, "Failed to create Cache Entry.\n");
      return FALSE;
    } else {
      fprintf(stdout, "Successfully created Cache Entry.\n");
      return TRUE;
    }
}


/**
 * ReadShadowFile:
 * @username: Username to read hashed password for.
 */
gboolean ReadShadowFile(const gchar *username, const gchar *path) {
  struct spwd *stmpent = NULL;
  int error = 0;
  
  if (!path) {
    path = "/etc/shadow";
  }

  FILE *shadowfile = fopen(path, "r");
  if (shadowfile == NULL) {
    error = 1;
    goto done;
  }

  // stmpent -- Read next shadow entry from STREAM.
  stmpent = fgetspent(shadowfile);
  // Loop through /etc/shadow file
  while (stmpent) {
    if (!strcmp(stmpent->sp_namp, username)) {
      // Create entry from shadow hash if username matches an entry.
      CreateEntryFromShadowHash(username, stmpent->sp_pwdp);
      break;
    }
    // Get the next shadow entry from STREAM
    fgetspent(shadowfile);
  }
  fclose(shadowfile);

  done:
    if (error) {
      fprintf(stderr, "Failed to read shadow file.\n");
    }

  if (!error) {
    fprintf(stdout, "Successfully read shadow file.\n");
    return TRUE;
  } else {
    fprintf(stderr, "Shadow read failed.\n");
    return FALSE;
  }
}


int main(int argc, char *argv[]) {
  int exit_code = 0;
  GError *error = NULL;
  GOptionContext *context = NULL;
 
  static gboolean add = FALSE;
  static gboolean unlock = FALSE;
  static gboolean lock = FALSE;
  static gchar* path = NULL;
  static GOptionEntry entries[] = 
    {
        { "lock", 'l', 0, G_OPTION_ARG_NONE, &lock, "Lock specified user's shadow hash password."},
        { "unlock", 'u', 0, G_OPTION_ARG_NONE, &unlock, "Unlock specified user's shadow hash password."}, 
        { "path", 'p', 0, G_OPTION_ARG_STRING, &path, "Path to search for hashed passwords."},
        { "add-policycache", 'a', 0, G_OPTION_ARG_NONE, &add, "Reads shadow hash password for a given user and adds it to policycache."},
	{ NULL }
    };

  context = g_option_context_new("- import shadow hash module");
  g_option_context_add_main_entries(context, entries, NULL);
  if (!g_option_context_parse(context, &argc, &argv, &error)) {
    goto done;
  }
  
  // Ensure the the application is running as root.
  int uid = getuid();
  if (uid != 0) {
    fprintf(stderr, "Must be run as root, please re-run as root.\n");
    goto done;
  }
  
    
  char *user = argv[1];
  if (add == TRUE && user != NULL) { 
    // Read shadow file and create policycache entry.
    ReadShadowFile(user, path);
  } else if (lock == TRUE && user != NULL) {
    // Lock specified user's password hash.
      LockUser(user);
  } else if (unlock == TRUE && user != NULL) {
    // Unlock specified user's password hash.
      UnlockUser(user);
  }
      
  done:
    if (error) {
      g_printerr("option parsing failed %s\n", error->message);
      g_error_free(error);
    }
    return exit_code;
}
