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

#ifndef CACHE_STORAGE_H_
#define CACHE_STORAGE_H_

#include <glib.h>

#include "entry.h"

#define CACHE_STORAGE_ERROR _CacheStorageErrorQuark()

/**
 * CacheStorage:
 * @refcount: Number of refences to this struct.
 * @path: Directory containing the cache entries.
 */
typedef struct {
  gint refcount;
  gchar *path;
} CacheStorage;

/**
 * CacheStorageError:
 * @CACHE_ENTRY_USERNAME_ERROR: Username contains unsupported characters.
 * @CACHE_STORAGE_FILE_ERROR: Error reading/writing the cache entry on disk.
 */
typedef enum {
  CACHE_STORAGE_USERNAME_ERROR,
  CACHE_STORAGE_FILE_ERROR,
} CacheStorageError;

CacheStorage *CacheStorageNew(const char *path);
void CacheStorageRef(CacheStorage *self);
void CacheStorageUnref(CacheStorage *self);

CacheEntry *CacheStorageGetEntry(CacheStorage *self, const gchar *username,
                                 GError **error);
gboolean CacheStoragePutEntry(CacheStorage *self, const gchar *username,
                              CacheEntry *entry, GError **error);

GQuark _CacheStorageErrorQuark();

#endif
