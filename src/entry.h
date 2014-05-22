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

#ifndef CACHE_ENTRY_H_
#define CACHE_ENTRY_H_

#include <glib.h>

#define CACHE_ENTRY_ERROR _CacheEntryErrorQuark()

/**
 * CacheEntry:
 * @refcount: Number of refences to the entry.
 * @version: Version when the entry was created/serialized, 1 for now.
 * @algorithm: Hash algorithm used in @hash.
 * @salt: Salt to concatenate before a password when calculating @hash.
 * @hash: Hashed @salt + password.
 * @last_verified: Date when CacheEntryPasswordSet() was last called.
 * @last_used: Date when CacheEntryPasswordValidate() last suceeded.
 * @last_tried: Date when CacheEntryPasswordValidate() was last called.
 * @tries: Number of calls to CacheEntryPasswordValidate() that have failed
 * since the last success.
 *
 * Stores the @salt, @hash, and other information about a single user in the
 * cache.
 */
typedef struct {
  gint refcount;
  gint version;
  GChecksumType algorithm;
  GBytes *salt;
  GBytes *hash;
  GDateTime *last_verified;
  GDateTime *last_used;
  GDateTime *last_tried;
  gint tries;
} CacheEntry;

/**
 * CacheEntryError:
 * @CACHE_ENTRY_UNKNOWN_ERROR: Unknown error.
 * @CACHE_ENTRY_EMPTY_ERROR: Value was an emtpy string.
 * @CACHE_ENTRY_PASSWORD_ERROR: Given password didn't match.
 * @CACHE_ENTRY_CORRUPT_ERROR: Entry has inconsistent attributes.
 * @CACHE_ENTRY_PARSE_ERROR: Couldn't parse the entry.
 *
 * Error codes returned by CacheEntry* functions.
 */
typedef enum {
  CACHE_ENTRY_UNKNOWN_ERROR,
  CACHE_ENTRY_EMPTY_ERROR,
  CACHE_ENTRY_PASSWORD_ERROR,
  CACHE_ENTRY_CORRUPT_ERROR,
  CACHE_ENTRY_PARSE_ERROR,
} CacheEntryError;

CacheEntry *CacheEntryNew();
void CacheEntryRef(CacheEntry *self);
void CacheEntryUnref(CacheEntry *self);

CacheEntry *CacheEntryUnserialize(const gchar *value, GError **error);
gchar *CacheEntrySerialize(CacheEntry *self);

gboolean CacheEntryPasswordSet(CacheEntry *self, const gchar *password,
                               GError **error);
gboolean CacheEntryPasswordValidate(CacheEntry *self, const gchar *password,
                                    GError **error);

GQuark _CacheEntryErrorQuark();

#endif
