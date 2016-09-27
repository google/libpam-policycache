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
#include <stdio.h>
#include <shadow.h>

#define SH_TMPFILE "/etc/nshadow"

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
 * UpdateShadowHash:
 * @username: Username to blank out hashed shadow password.
 * @towhat: What to changed the hashed password to.
 */
gboolean UpdateShadowHash(const gchar *username, gchar *towhat) {
  struct spwd *stmpent = NULL;

  FILE *pwfile, *opwfile;
  int error = 0;
  int oldmask = umask(077);
  int wroteentry = 0;


  pwfile = fopen(SH_TMPFILE, "w");
  umask(oldmask);
  if (pwfile == NULL) {
    error = 1;
    goto done;
  }

  opwfile = fopen("/etc/shadow", "r");
  if (opwfile == NULL) {
    fclose(pwfile);
    error = 1;
    goto done;
  }

  // stmpent -- Read next shadow entry from STREAM.
  stmpent = fgetspent(opwfile);
  // Loop through /etc/shadow file
  while (stmpent) {
    if (!strcmp(stmpent->sp_namp, username)) {
      // Create entry from shadow hash if username matches an entry.
      CreateEntryFromShadowHash(username, stmpent->sp_pwdp);
      // Set encrypted password to towhat
      stmpent->sp_pwdp = towhat;
      stmpent->sp_lstchg = time(NULL) / (60 * 60 * 24);
      // Check that an entry was written.
      wroteentry = 1;
      fprintf(stdout, "Set password %s for %s\n", stmpent-> sp_pwdp, username);
    }

    if (putspent(stmpent, pwfile)) {
      fprintf(stderr, "Error writting entry to shadow file\n");
      error = 1;
      break;
    }

    stmpent = fgetspent(opwfile);
  }

  fclose(opwfile);

  done:
    if (!error) {
      // Move tmp file contents into the real file.
      if (!rename(SH_TMPFILE, "/etc/shadow"))
          fprintf(stdout, "Password changed for %s\n", username);
      else
          error = 1;
    }

  if (!error) {
    fprintf(stdout, "Successfully updated shadow file.\n");
    return TRUE;
  } else {
    unlink(SH_TMPFILE);
    fprintf(stderr, "Failed to update shadow file.\n");
    return FALSE;
  }
}

int main(int argc, char *argv[]) {
  int exit_code = 0;
  GError *error = NULL;
  GOptionContext *context = NULL;
 
  // TODO(mcclunge): Add option to disable hash password instead of just remove.
  static gboolean remove = FALSE; 
  static gchar* username = NULL;
  static GOptionEntry entries[] = 
    {
	{ "remove", 'r', 0, G_OPTION_ARG_NONE, &remove, "Remove shadow hash password for a given user."},
        { "username", 'u', 0, G_OPTION_ARG_STRING, &username, "Username to affect changes on."},
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
  if (!username) {
    fprintf(stderr, "Command must include username argument.\n");
    goto done;

  } else { 
      if (remove == TRUE) {
        // Remove hashed password by replacing it with "*".
        UpdateShadowHash(username, "*");
      } else {
	  fprintf(stderr, "Command must include -r to remove shadow hash.\n");
      }
  }

  done:
    if (error) {
      g_printerr("option parsing failed %s\n", error->message);
      g_error_free(error);
    }
    return exit_code;
}
