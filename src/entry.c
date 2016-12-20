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

#include "entry.h"

#include <crypt.h>
#include <string.h>

#include <libscrypt.h>

#include "util.h"

#define CACHE_ENTRY_DEFAULT_ALGORITHM G_CHECKSUM_SHA256
#define CACHE_ENTRY_DEFAULT_SALT_LENGTH 16


/**
 * CacheEntryNew:
 *
 * Returns: #CacheEntry instance with a reference count of one.
 */
CacheEntry *CacheEntryNew() {
  CacheEntry *self = g_new0(CacheEntry, 1);
  self->refcount = 1;
  self->algorithm = CACHE_ENTRY_ALGORITHM_UNKNOWN;
  return self;
}


void CacheEntryRef(CacheEntry *self) {
  g_assert(self->refcount > 0);
  self->refcount++;
}


static void CacheEntryFreeArgs(CacheEntry *self) {
  if (self->args.basic_salt)
    g_bytes_unref(self->args.basic_salt);
  if (self->args.scrypt_salt)
    g_bytes_unref(self->args.scrypt_salt);
  memset(&self->args, 0, sizeof(self->args));
}


void CacheEntryUnref(CacheEntry *self) {
  g_assert(self->refcount > 0);
  self->refcount--;
  if (self->refcount)
    return;

  CacheEntryFreeArgs(self);

  if (self->hash)
    g_bytes_unref(self->hash);
  if (self->last_verified)
    g_date_time_unref(self->last_verified);
  if (self->last_used)
    g_date_time_unref(self->last_used);
  if (self->last_tried)
    g_date_time_unref(self->last_tried);

  memset(self, 0, sizeof(*self));
  g_free(self);
}


/**
 * CacheEntryUnserialize:
 * @value: Serialized cache entry.
 * @error: (out)(allow-none): Error return location or #NULL.
 *
 * Returns: #CacheEntry instance with a reference count of one and attributes
 * filled in from parsing @value.
 */
CacheEntry *CacheEntryUnserialize(const gchar *value, GError **error) {
  GError *parse_error = NULL;
  GVariant *dict = NULL;
  GVariant *args = NULL;
  CacheEntry *self = NULL;
  gint version = 0;
  const gchar *tmp_str = NULL;

  dict = g_variant_parse(
      G_VARIANT_TYPE_VARDICT, value, NULL, NULL, &parse_error);
  if (!dict) {
    g_assert(parse_error);
    g_set_error(error, CACHE_ENTRY_ERROR, CACHE_ENTRY_PARSE_ERROR,
                "Failed to parse cache entry: %s", parse_error->message);
    g_error_free(parse_error);
    return NULL;
  }

  g_variant_lookup(dict, "version", "i", &version);
  switch (version) {
  case 1:
    args = dict;
    g_variant_ref(dict);
    break;
  case 2:
    args = g_variant_lookup_value(dict, "args", G_VARIANT_TYPE_VARDICT);
    break;
  default:
    g_set_error(error, CACHE_ENTRY_ERROR, CACHE_ENTRY_PARSE_ERROR,
                "Entry version %d not supported", version);
    goto done;
  }

  if (!args) {
    g_set_error(error, CACHE_ENTRY_ERROR, CACHE_ENTRY_PARSE_ERROR,
                "Entry has no 'args' attribute");
    goto done;
  }

  if (!g_variant_lookup(dict, "algorithm", "&s", &tmp_str)) {
    g_set_error(error, CACHE_ENTRY_ERROR, CACHE_ENTRY_PARSE_ERROR,
                "Entry has no 'algorithm' attribute");
    goto done;
  }

  self = g_new0(CacheEntry, 1);
  self->refcount = 1;

  if (g_str_equal(tmp_str, "SHA256")) {
    self->algorithm = CACHE_ENTRY_ALGORITHM_SHA256;
    if (g_variant_lookup(args, "salt", "&s", &tmp_str))
      CacheUtilBytesFromString(tmp_str, &self->args.basic_salt);
  } else if (g_str_equal(tmp_str, "scrypt")) {
    self->algorithm = CACHE_ENTRY_ALGORITHM_SCRYPT;
    if (g_variant_lookup(args, "salt", "&s", &tmp_str))
      CacheUtilBytesFromString(tmp_str, &self->args.scrypt_salt);
    g_variant_lookup(args, "N", "t", &self->args.scrypt_N);
    g_variant_lookup(args, "r", "u", &self->args.scrypt_r);
    g_variant_lookup(args, "p", "u", &self->args.scrypt_p);
  } else if (g_str_equal(tmp_str, "crypt")) {
    self->algorithm = CACHE_ENTRY_ALGORITHM_CRYPT;
  } else {
    g_free(self);
    self = NULL;
    g_set_error(error, CACHE_ENTRY_ERROR, CACHE_ENTRY_PARSE_ERROR,
                "Unknown entry algorithm '%s'", tmp_str);
    goto done;
  }

  g_variant_lookup(dict, "tries", "i", &self->tries);

  if (g_variant_lookup(dict, "hash", "&s", &tmp_str))
    CacheUtilBytesFromString(tmp_str, &self->hash);

  if (g_variant_lookup(dict, "last_verified", "&s", &tmp_str))
    CacheUtilDatetimeFromString(tmp_str, &self->last_verified);
  if (g_variant_lookup(dict, "last_used", "&s", &tmp_str))
    CacheUtilDatetimeFromString(tmp_str, &self->last_used);
  if (g_variant_lookup(dict, "last_tried", "&s", &tmp_str))
    CacheUtilDatetimeFromString(tmp_str, &self->last_tried);

done:
  g_variant_unref(dict);
  if (args)
    g_variant_unref(args);
  return self;
}


/**
 * CacheEntrySerialize:
 * @self: #CacheEntry to serialize.
 *
 * Returns: Human-readable string representing @self.
 */
gchar *CacheEntrySerialize(CacheEntry *self) {
  GVariantBuilder builder;
  gchar *tmp_str = NULL;
  const gchar *algorithm = NULL;
  GVariant *args = NULL;
  GVariant *result_variant = NULL;
  gchar *result = NULL;

  g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);
  switch (self->algorithm) {
  case CACHE_ENTRY_ALGORITHM_SHA256:
    algorithm = "SHA256";
    if (self->args.basic_salt) {
      tmp_str = CacheUtilBytesToString(self->args.basic_salt);
      g_variant_builder_add(&builder, "{sv}", "salt",
                            g_variant_new_string(tmp_str));
      g_free(tmp_str);
    }
    break;
  case CACHE_ENTRY_ALGORITHM_SCRYPT:
    algorithm = "scrypt";
    if (self->args.scrypt_salt) {
      tmp_str = CacheUtilBytesToString(self->args.scrypt_salt);
      g_variant_builder_add(&builder, "{sv}", "salt",
                            g_variant_new_string(tmp_str));
      g_free(tmp_str);
    }
    g_variant_builder_add(&builder, "{sv}", "N",
                          g_variant_new_uint64(self->args.scrypt_N));
    g_variant_builder_add(&builder, "{sv}", "r",
                          g_variant_new_uint32(self->args.scrypt_r));
    g_variant_builder_add(&builder, "{sv}", "p",
                          g_variant_new_uint32(self->args.scrypt_p));
    break;
  case CACHE_ENTRY_ALGORITHM_CRYPT:
    algorithm = "crypt";
    break;
  default:
    g_assert_not_reached();
  }
  args = g_variant_builder_end(&builder);

  g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);
  g_variant_builder_add(&builder, "{sv}", "version",
                        g_variant_new_int32(2));
  g_variant_builder_add(&builder, "{sv}", "tries",
                        g_variant_new_int32(self->tries));
  g_variant_builder_add(&builder, "{sv}", "algorithm",
                        g_variant_new_string(algorithm));
  g_variant_builder_add(&builder, "{sv}", "args", args);

  struct {const gchar *name; gchar *value;} attrs[] = {
    {"hash", CacheUtilBytesToString(self->hash)},
    {"last_verified", CacheUtilDatetimeToString(self->last_verified)},
    {"last_used", CacheUtilDatetimeToString(self->last_used)},
    {"last_tried", CacheUtilDatetimeToString(self->last_tried)},
  };

  for (guint i = 0; i < G_N_ELEMENTS(attrs); i++) {
    if (attrs[i].value) {
      g_variant_builder_add(&builder, "{sv}", attrs[i].name,
                            g_variant_new_string(attrs[i].value));
      g_free(attrs[i].value);
    }
  }

  result_variant = g_variant_builder_end(&builder);
  result = g_variant_print(result_variant, TRUE);
  g_variant_unref(result_variant);
  return result;
}


/**
 * CacheEntryUpdateTime:
 * @time_ptr: (inout): #GDateTime instance to set to @now. If the pointer was
 * non-NULL, g_date_time_unref() is called on it first.
 * @now: New value for *@time_ptr.
 */
static void CacheEntryUpdateTime(GDateTime **time_ptr, GDateTime *now) {
  if (*time_ptr)
    g_date_time_unref(*time_ptr);
  *time_ptr = now;
  g_date_time_ref(now);
}


/**
 * CacheEntryPasswordSet:
 * @self: Instance to update.
 * @password: Password used in the new #CacheEntry.hash.
 * @error: (out)(allow-none): Error return location or #NULL.
 *
 * Generates a new salt, sets hash with the salt and @password, and updates all
 * of the last_* values with the current time
 *
 * Returns: #TRUE if #CacheEntry.args and #CacheEntry.hash were updated, or
 * #FALSE if neither was updated.
 */
gboolean CacheEntryPasswordSet(CacheEntry *self, const gchar *password,
                               GError **error) {
  GDateTime *now = NULL;
  GBytes *salt = NULL;
  guint8 *hash = NULL;

  if (!password || password[0] == '\0') {
    g_set_error(error, CACHE_ENTRY_ERROR, CACHE_ENTRY_UNUSABLE_PASSWORD_ERROR,
                "Password must not be empty");
    return FALSE;
  }

  // TODO(vonhollen): Make the algorithm used for new entries configurable.
  salt = CacheUtilRandomBytes(CACHE_ENTRY_DEFAULT_SALT_LENGTH);
  hash = g_new0(guint8, SCRYPT_HASH_LEN);
  if (libscrypt_scrypt((const guint8 *) password, strlen(password),
                       g_bytes_get_data(salt, NULL), g_bytes_get_size(salt),
                       SCRYPT_N, SCRYPT_r, SCRYPT_p,
                       hash, SCRYPT_HASH_LEN)) {
    g_set_error(error, CACHE_ENTRY_ERROR, CACHE_ENTRY_UNKNOWN_ERROR,
                "Unknown libscrypt_scrypt() error, this is a bug");
    g_bytes_unref(salt);
    return FALSE;
  }

  CacheEntryFreeArgs(self);

  self->algorithm = CACHE_ENTRY_ALGORITHM_SCRYPT;
  self->args.scrypt_N = SCRYPT_N;
  self->args.scrypt_r = SCRYPT_r;
  self->args.scrypt_p = SCRYPT_p;
  self->args.scrypt_salt = salt;

  if (self->hash)
    g_bytes_unref(self->hash);
  self->hash = g_bytes_new_take(hash, SCRYPT_HASH_LEN);

  now = g_date_time_new_now_utc();
  CacheEntryUpdateTime(&self->last_verified, now);
  CacheEntryUpdateTime(&self->last_used, now);
  CacheEntryUpdateTime(&self->last_tried, now);
  g_date_time_unref(now);

  self->tries = 0;
  return TRUE;
}

void CacheEntryHashSet(CacheEntry *self, CacheEntryAlgorithm algorithm,
                  GBytes *hash, CacheEntryArgs *args) {
  self->algorithm = algorithm;
  self->hash = g_bytes_ref(hash);
}

/**
 * CacheEntryPasswordValidate:
 * @self: Instance with salt/hash to check @password against.
 * @password: Password to check.
 * @error: (out)(allow-none): Error return location or #NULL.
 *
 * Returns: #TRUE if the password matches, or #FALSE if there was an error and
 * @error was set. Not matching is considered an error.
 */
gboolean CacheEntryPasswordValidate(CacheEntry *self, const gchar *password,
                                    GError **error) {
  GBytes *hash = NULL;
  GDateTime *now = NULL;
  gboolean result = FALSE;

  // These are initialized and cleaned up in the relevant switch/case
  // statements.
  guint8 *hash_buf = NULL;
  GByteArray *salt = NULL;
  struct crypt_data crypt_state;
  char *hash_str = NULL;

  if (!self->hash) {
    g_set_error(error, CACHE_ENTRY_ERROR, CACHE_ENTRY_EMPTY_ERROR,
                "No cached password is available");
    return FALSE;
  }

  if (!password || password[0] == '\0') {
    g_set_error(error, CACHE_ENTRY_ERROR, CACHE_ENTRY_UNUSABLE_PASSWORD_ERROR,
                "Password must not be empty");
    return FALSE;
  }

  switch (self->algorithm) {
  case CACHE_ENTRY_ALGORITHM_SHA256:
    hash = CacheUtilHashPassword(G_CHECKSUM_SHA256, self->args.basic_salt,
                                 password);
    if (!hash) {
      g_set_error(error, CACHE_ENTRY_ERROR, CACHE_ENTRY_CORRUPT_ERROR,
                  "Unknown hash function error");
      return FALSE;
    }
    break;
  case CACHE_ENTRY_ALGORITHM_SCRYPT:
    hash_buf = g_new0(guint8, g_bytes_get_size(self->hash));
    if (libscrypt_scrypt((const guint8 *) password, strlen(password),
                         g_bytes_get_data(self->args.scrypt_salt, NULL),
                         g_bytes_get_size(self->args.scrypt_salt),
                         self->args.scrypt_N,
                         self->args.scrypt_r,
                         self->args.scrypt_p,
                         hash_buf, g_bytes_get_size(self->hash))) {
      g_set_error(error, CACHE_ENTRY_ERROR, CACHE_ENTRY_CORRUPT_ERROR,
                  "Unknown libscrypt_scrypt() error");
      g_free(hash_buf);
      return FALSE;
    }
    hash = g_bytes_new_take(hash_buf, g_bytes_get_size(self->hash));
    break;
  case CACHE_ENTRY_ALGORITHM_CRYPT:
    // The salt for crypt() when verifying a password is the entire expected
    // hash as a NULL-terminated string. crypt() will use the algorithm/salt
    // identifiers and ignore the hash value.
    salt = g_byte_array_sized_new(g_bytes_get_size(self->hash) + 1);
    g_byte_array_append(salt, g_bytes_get_data(self->hash, NULL),
                        g_bytes_get_size(self->hash));
    g_byte_array_append(salt, (const guint8 *) "\0", 1);
    crypt_state.initialized = 0;
    hash_str = crypt_r(password, (const char *) salt->data, &crypt_state);
    g_byte_array_unref(salt);
    hash = g_bytes_new(hash_str, strlen(hash_str));
    break;
  default:
    g_set_error(error, CACHE_ENTRY_ERROR, CACHE_ENTRY_CORRUPT_ERROR,
                "Unknown entry algorithm %d", self->algorithm);
    return FALSE;
  }

  now = g_date_time_new_now_utc();
  CacheEntryUpdateTime(&self->last_tried, now);

  g_assert(hash);
  if (g_bytes_equal(hash, self->hash)) {
    CacheEntryUpdateTime(&self->last_used, now);
    self->tries = 0;
    result = TRUE;
  } else {
    self->tries++;
    g_set_error(error, CACHE_ENTRY_ERROR, CACHE_ENTRY_PASSWORD_ERROR,
                "Password doesn't match cached value");
  }

  g_bytes_unref(hash);
  g_date_time_unref(now);
  return result;
}


GQuark
_CacheEntryErrorQuark() {
  return g_quark_from_string("cache-entry-error-quark");
}
