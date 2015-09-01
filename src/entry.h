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
 * CacheEntryAlgorithm:
 * @CACHE_ENTRY_ALGORITHM_SHA256: Algorithm for string "SHA256". Least secure
 * option available.
 * @CACHE_ENTRY_ALGORITHM_SCRYPT: Algorithm for string "scrypt". Scrypt is the
 * default and most secure option.
 * @CACHE_ENTRY_ALGORITHM_CRYPT: Algorithm for string "crypt". Uses crypt().
 *
 * Algorithms a CacheEntry can use to hash a password.
 */
typedef enum {
  CACHE_ENTRY_ALGORITHM_UNKNOWN = 0,
  CACHE_ENTRY_ALGORITHM_SHA256,
  CACHE_ENTRY_ALGORITHM_SCRYPT,
  CACHE_ENTRY_ALGORITHM_CRYPT,
} CacheEntryAlgorithm;

/**
 * CacheEntryBasicArgs:
 * @salt: Bytes hashed before the password.
 *
 * Arguments for basic hash functions like SHA*.
 */
typedef struct {
  GBytes *salt;
} CacheEntryBasicArgs;

/**
 * CacheEntryScryptArgs:
 * @salt: Bytes used to perturb the hash.
 * @N: Primary work factor. Must be a power of two.
 * @r: Memory cost.
 * @p: CPU cost.
 *
 * Arguments for the scrypt algorithm.
 */
typedef struct {
  GBytes *salt;
  guint64 N;
  guint32 r;
  guint32 p;
} CacheEntryScryptArgs;

/**
 * CacheEntryArgs:
 * @basic: Args for basic hash algorithms like SHA256.
 * @scrypt: Args for the scrypt algorithm.
 *
 * Arguments depend on the algorithm selected in the CacheEntry.
 */
typedef union {
  CacheEntryBasicArgs basic;
  CacheEntryScryptArgs scrypt;
} CacheEntryArgs;

/**
 * CacheEntry:
 * @refcount: Number of refences to the entry.
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
  CacheEntryAlgorithm algorithm;
  CacheEntryArgs args;
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
 * @CACHE_ENTRY_UNUSABLE_PASSWORD_ERROR: Given password was #NULL or empty.
 *
 * Error codes returned by CacheEntry* functions.
 */
typedef enum {
  CACHE_ENTRY_UNKNOWN_ERROR,
  CACHE_ENTRY_EMPTY_ERROR,
  CACHE_ENTRY_PASSWORD_ERROR,
  CACHE_ENTRY_CORRUPT_ERROR,
  CACHE_ENTRY_PARSE_ERROR,
  CACHE_ENTRY_UNUSABLE_PASSWORD_ERROR,
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
