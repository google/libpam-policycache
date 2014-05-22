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
#include "util.h"

#include <string.h>

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
  self->version = 1;
  self->algorithm = CACHE_ENTRY_DEFAULT_ALGORITHM;
  return self;
}


void CacheEntryRef(CacheEntry *self) {
  g_assert(self->refcount > 0);
  self->refcount++;
}


void CacheEntryUnref(CacheEntry *self) {
  g_assert(self->refcount > 0);
  self->refcount--;
  if (self->refcount)
    return;

  if (self->salt)
    g_bytes_unref(self->salt);
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
  if (version != 1) {
    g_set_error(error, CACHE_ENTRY_ERROR, CACHE_ENTRY_PARSE_ERROR,
                "Entry version %d not supported", version);
    goto done;
  }

  // TODO(vonhollen): Check for all of the keys so we know each g_variant_lookup
  // will work, then add error handling to each CacheUtil*FromString() call.

  self = CacheEntryNew();
  g_variant_lookup(dict, "tries", "i", &self->tries);

  if (g_variant_lookup(dict, "algorithm", "&s", &tmp_str))
    CacheUtilHashalgFromString(tmp_str, &self->algorithm);

  if (g_variant_lookup(dict, "salt", "&s", &tmp_str))
    CacheUtilBytesFromString(tmp_str, &self->salt);
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
  const gchar *algorithm = NULL;
  GVariant *result_variant = NULL;
  gchar *result = NULL;

  g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);
  g_variant_builder_add(&builder, "{sv}", "version",
                        g_variant_new_int32(self->version));
  g_variant_builder_add(&builder, "{sv}", "tries",
                        g_variant_new_int32(self->tries));

  algorithm = CacheUtilHashalgToString(self->algorithm);
  if (algorithm)
    g_variant_builder_add(&builder, "{sv}", "algorithm",
                          g_variant_new_string(algorithm));

  struct {const gchar *name; gchar *value;} attrs[] = {
    {"salt", CacheUtilBytesToString(self->salt)},
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
 * Returns: #TRUE if #CacheEntry.salt and #CacheEntry.hash were updated, or
 * #FALSE if neither was updated.
 */
gboolean CacheEntryPasswordSet(CacheEntry *self, const gchar *password,
                               GError **error) {
  GDateTime *now = NULL;
  GBytes *salt = NULL;
  GBytes *hash = NULL;

  salt = CacheUtilRandomBytes(CACHE_ENTRY_DEFAULT_SALT_LENGTH);
  g_assert(salt);

  hash = CacheUtilHashPassword(self->algorithm, salt, password);
  if (!hash) {
    g_set_error(error, CACHE_ENTRY_ERROR, CACHE_ENTRY_CORRUPT_ERROR,
                "Unknow hash algorithm selected");
    g_bytes_unref(salt);
    return FALSE;
  }

  if (self->salt)
    g_bytes_unref(self->salt);
  self->salt = salt;

  if (self->hash)
    g_bytes_unref(self->hash);
  self->hash = hash;

  now = g_date_time_new_now_utc();
  CacheEntryUpdateTime(&self->last_verified, now);
  CacheEntryUpdateTime(&self->last_used, now);
  CacheEntryUpdateTime(&self->last_tried, now);
  g_date_time_unref(now);

  self->tries = 0;
  return TRUE;
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

  if (!self->salt || !self->hash) {
    g_set_error(error, CACHE_ENTRY_ERROR, CACHE_ENTRY_EMPTY_ERROR,
                "No cached password is available");
    return FALSE;
  }

  hash = CacheUtilHashPassword(self->algorithm, self->salt, password);
  if (!hash) {
    g_set_error(error, CACHE_ENTRY_ERROR, CACHE_ENTRY_CORRUPT_ERROR,
                "Unknow hash algorithm selected");
    return FALSE;
  }

  now = g_date_time_new_now_utc();
  CacheEntryUpdateTime(&self->last_tried, now);

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
  return g_quark_from_static_string("cache-entry-error-quark");
}
