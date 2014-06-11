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

#ifndef CACHE_MODULE_H_
#define CACHE_MODULE_H_

#include <glib.h>

// TODO(vonhollen): Use variable from Makefile instead.
#define DEFAULT_POLICY_PATH "/etc/libpam-policycache.d/*.conf"
#define DEFAULT_STORAGE_PATH "/var/cache/libpam-policycache.d"

#define CACHE_MODULE_ERROR _CacheModuleErrorQuark()

typedef enum {
  CACHE_MODULE_REPEAT_ARGUMENT_ERROR,
  CACHE_MODULE_INVALID_ARGUMENT_ERROR,
  CACHE_MODULE_UNKNOWN_ARGUMENT_ERROR,
  CACHE_MODULE_NO_POLICY_ERROR,
  CACHE_MODULE_NO_ACTION_ERROR,
} CacheModuleError;

typedef enum {
  CACHE_MODULE_UNKNOWN_ACTION,
  CACHE_MODULE_CHECK_ACTION,
  CACHE_MODULE_RECALL_ACTION,
  CACHE_MODULE_UPDATE_ACTION,
} CacheModuleAction;

typedef struct {
  int pam_flags;
  gchar *username;
  gboolean try_first_pass;
  gboolean use_first_pass;
  gchar *policy_path;
  gchar *storage_path;
  CacheModuleAction action;
  GHashTable *args_seen;
} CacheModule;

CacheModule *CacheModuleNew(const gchar *username, int pam_flags);
void CacheModuleFree(CacheModule *self);

gboolean CacheModuleAddArg(CacheModule *self, const gchar *arg, GError **error);
int CacheModuleDoAction(CacheModule *self, const gchar *password,
                        GError **error);

GQuark _CacheModuleErrorQuark();

#endif
