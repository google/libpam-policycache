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

#include "util.h"

#include <errno.h>
#include <glob.h>
#include <grp.h>
#include <pwd.h>
#include <string.h>
#include <shadow.h>
#include <stdio.h>
#include <sys/types.h>

typedef struct {
  const gchar *name;
  GChecksumType type;
} CacheUtilNameToHashAlg;

static CacheUtilNameToHashAlg name_to_hashalg[] = {
  {"MD5", G_CHECKSUM_MD5},
  {"SHA1", G_CHECKSUM_SHA1},
  {"SHA256", G_CHECKSUM_SHA256},
#if GLIB_CHECK_VERSION(2, 37, 0)
  {"SHA512", G_CHECKSUM_SHA512},
#endif
};


/**
 * CacheUtilDatetimeToString:
 * @value: Date to create string from. Must be UTC.
 *
 * Returns: (allow-none): Date in "{yyyy}-{mm}-{dd}T{hh}:{mm}:{ss}Z" format
 * (ISO 8601) or #NULL if the date couldn't be serialized.
 */
gchar *CacheUtilDatetimeToString(GDateTime *value) {
  if (!value)
    return NULL;

  return g_date_time_format_iso8601(value);
}


/**
 * CacheUtilDatetimeFromString:
 * @value: String containing the date, in the "{yyyy}-{mm}-{dd}T{hh}:{mm}:{ss}Z"
 * format (ISO 8601). Dates are always UTC.
 * @result: (out): GDateTime respresenting the given @value.
 *
 * Returns: #TRUE if @result was modified or #FALSE if the date couldn't be
 * parsed.
 */
gboolean CacheUtilDatetimeFromString(const gchar *value, GDateTime **result) {
  g_assert(result);

  GTimeZone *tz = g_time_zone_new_utc();
  GDateTime *dt = g_date_time_new_from_iso8601(value, tz);
  g_time_zone_unref(tz);
  if (!dt)
    return FALSE;

  *result = dt;
  return TRUE;
}


/**
 * CacheUtilHashalgToString:
 * @value: Hash algorithm to return name for.
 *
 * Returns: Name of the algorithm in @value, like "SHA256", or #NULL if the
 * algorithm isn't known.
 */
const gchar *CacheUtilHashalgToString(GChecksumType value) {
  for (guint i = 0; i < G_N_ELEMENTS(name_to_hashalg); i++) {
    if (name_to_hashalg[i].type == value) {
      return name_to_hashalg[i].name;
    }
  }
  return NULL;
}


/**
 * CacheUtilHashalgFromString:
 * @value: String containing a hash algorithm name, like "SHA1" or "SHA256".
 * @result: (out): GChecksumType with the same name.
 *
 * Returns: #TRUE if @result was modified or #FALSE if the algorithm in @value
 * isn't known.
 */
gboolean CacheUtilHashalgFromString(const gchar *value, GChecksumType *result) {
  g_assert(result);
  for (guint i = 0; i < G_N_ELEMENTS(name_to_hashalg); i++) {
    if (strcmp(name_to_hashalg[i].name, value) == 0) {
      *result = name_to_hashalg[i].type;
      return TRUE;
    }
  }
  return FALSE;
}


/**
 * CacheUtilReadShadowFile:
 * @path: Shadow file path.
 * @username: Username to read hashed password for.
 * @error Error return location or #NULL. 
 *
 * Returns: GByte hash for user, or #NULL on error. 
 */

GBytes *CacheUtilReadShadowFile(const gchar *path, const gchar *username, GError **error) {
  struct spwd *stmpent = NULL;
  
  FILE *shadowfile = fopen(path, "r");
  if (shadowfile == NULL) {
    g_set_error(error, UTIL_ERROR, UTIL_ERROR_NO_OPEN_FILE, "Failed to open file: %s",  g_strerror(errno));
    return NULL;
  }

  while ((stmpent = fgetspent(shadowfile))) {
    if (!strcmp(stmpent->sp_namp, username)) {
      // Return matching shadow hash value.
      GBytes* hash = g_bytes_new(stmpent->sp_pwdp, strlen(stmpent->sp_pwdp));
      fclose(shadowfile);
      return hash;
    }
  }
  fclose(shadowfile);
  g_set_error(error, UTIL_ERROR, UTIL_ERROR_NO_HASH, "Could not find shadow hash.");
  return NULL;
}


  /**
 * CacheUtilBytesToString:
 * @value: Raw bytes to encode.
 *
 * Returns: String containing only hex-digits.
 */
gchar *CacheUtilBytesToString(GBytes *value) {
  static gchar hex_digits [] = "0123456789ABCDEF";
  const guint8 *value_data = NULL;
  gsize value_len = 0;
  gchar *result = NULL;

  if (!value)
    return NULL;

  value_data = (const guint8 *) g_bytes_get_data(value, &value_len);
  result = g_malloc(value_len * 2 + 1);
  result[value_len * 2] = '\0';

  for (guint i = 0; i < value_len; i++) {
    gsize result_pos = i * 2;
    result[result_pos] = hex_digits[value_data[i] >> 4];
    result[result_pos + 1] = hex_digits[value_data[i] & 0x0F];
  }

  return result;
}


/**
 * CacheUtilBytesFromString:
 * @value: String containing an even number of hex-digits.
 * @result: (out): Raw bytes used to encode the hex value.
 *
 * Returns: #TRUE if @result was modified or #FALSE if the string was not valid
 * hex-encoded bytes.
 */
gboolean CacheUtilBytesFromString(const gchar *value, GBytes **result) {
  g_assert(result);
  if (!value)
    return FALSE;

  gsize value_len = strlen(value);
  gsize result_len = value_len / 2;
  guint8 result_data[result_len];

  // Hex strings must have a length that's a multiple of two.
  if (value_len & 0x01)
    return FALSE;

  for (guint i = 0; i < value_len; i += 2) {
    gint nibble1 = g_ascii_xdigit_value(value[i]);
    gint nibble2 = g_ascii_xdigit_value(value[i + 1]);
    if (nibble1 < 0 || nibble2 < 0) {
      return FALSE;
    }
    result_data[i >> 1] = (nibble1 << 4) | nibble2;
  }

  *result = g_bytes_new(result_data, result_len);
  return TRUE;
}


/**
 * CacheUtilHashPassword:
 * @algorithm: Hash algorithm.
 * @salt: Random data, usually stored with the hash.
 * @password: Secret value to hash.
 *
 * Returns: (allow-none): Hash value of concatenated @salt and @password, or
 * #NULL if an argument was invalid.
 */
GBytes *CacheUtilHashPassword(GChecksumType algorithm, GBytes *salt,
                               const char *password) {
  GChecksum *checksum = NULL;
  gssize checksum_len = -1;
  guint8 *result = NULL;
  gsize result_len = 0;

  if (!salt || !password)
    return NULL;

  checksum_len = g_checksum_type_get_length(algorithm);
  if (checksum_len <= 0)
    return NULL;

  checksum = g_checksum_new(algorithm);
  if (!checksum)
    return NULL;

  g_checksum_update(
      checksum, g_bytes_get_data(salt, NULL), g_bytes_get_size(salt));
  g_checksum_update(checksum, (guint8 *) password, strlen(password));

  result = g_malloc(checksum_len);
  result_len = checksum_len;

  g_checksum_get_digest(checksum, result, &result_len);
  g_assert(checksum_len == result_len);

  g_checksum_free(checksum);
  return g_bytes_new_take(result, result_len);
}


/**
 * CacheUtilRandomBytes:
 * @size: Number of bytes to return.
 *
 * Returns: @size bytes of random data.
 */
GBytes *CacheUtilRandomBytes(gsize size) {
  // Create an array of ints a little longer than @size bytes and fill it with
  // random numbers. Each array element covers 4 bytes of the final result.
  gsize random_ints_len = size / 4 + 1;
  guint32 *random_ints = g_new(guint32, random_ints_len);
  for (guint i = 0; i < random_ints_len; i++) {
    random_ints[i] = g_random_int();
  }
  return g_bytes_new_take(random_ints, size);
}


/**
 * CacheUtilGetGroupsForUser:
 * @username: Username to list groups for.
 *
 * Returns: (array zero-terminated=1)(allow-none): Array of group names, or
 * #NULL if @username is not a real user.
 */
gchar **CacheUtilGetGroupsForUser(const gchar *username) {
  const struct passwd *user_entry = NULL;
  gid_t user_gid = 0;
  int num_groups = 64;  // Overwritten by first call to getgrouplist.
  gid_t *groups = NULL;
  int infinite_loop_check = 0;
  gchar **result = NULL;
  guint next_result = 0;

  user_entry = getpwnam(username);
  if (!user_entry) {
    return NULL;
  }

  user_gid = user_entry->pw_gid;

  do {
    g_assert(num_groups > 0);
    g_assert(infinite_loop_check++ < 10);
    g_free(groups);
    groups = g_new(gid_t, num_groups);
  } while (getgrouplist(username, user_gid, groups, &num_groups) == -1);

  result = g_new0(gchar *, num_groups + 1);
  for (guint i = 0; i < num_groups; i++) {
    const struct group *group_entry = getgrgid(groups[i]);
    if (group_entry) {
      result[next_result] = g_strdup(group_entry->gr_name);
      next_result++;
    }
  }

  g_free(groups);
  return result;
}


/**
 * CacheUtilTimeSpanFromString:
 * @value: String containing a positive integer with an suffix, like "5d" for 5
 * days or "1w" for one week.
 * @result: (out): Pointer to the resulting GTimeSpan.
 *
 * Valid suffixes are "w" (weeks), "d" (days), and "h" (hours).
 *
 * Returns: #TRUE if @value is valid and @result was updated.
 */
gboolean CacheUtilTimespanFromString(const gchar *value, GTimeSpan *result) {
  gchar *suffix = NULL;
  gint64 multiple = 0;

  gint64 number = g_ascii_strtoll(value, &suffix, 10);
  if (!suffix || strlen(suffix) != 1 || suffix == value)
    return FALSE;

  switch (suffix[0]) {
    case 'm':
      multiple = G_TIME_SPAN_MINUTE;
      break;
    case 'h':
      multiple = G_TIME_SPAN_HOUR;
      break;
    case 'd':
      multiple = G_TIME_SPAN_DAY;
      break;
    case 'w':
      multiple = G_TIME_SPAN_DAY * 7;
      break;
    default:
      return FALSE;
  }

  *result = number * multiple;
  return TRUE;
}


/**
 * CacheUtilSplitString:
 * @value: String to split.
 * @delim: String used to split @value into two pieces.
 * @left: (out): On success, contains the string on the left side of @delim.
 * @right: (out): On success, contains the string on the right side of @delim.
 *
 * Returns: #TRUE if the string was split into exactly two parts.
 */
gboolean CacheUtilSplitString(const gchar *value, const gchar *delim,
                              gchar **left, gchar **right) {
  gchar **parts = g_strsplit(value, delim, 2);
  if (!parts)
    return FALSE;

  if (g_strv_length(parts) == 2) {
    *left = parts[0];
    *right = parts[1];
    g_free(parts);  // Only the array is freed, not the string results.
    return TRUE;
  } else {
    g_strfreev(parts);  // No results, so free the array and child strings.
    return FALSE;
  }
}


/**
 * CacheUtilStringArrayContains:
 * @values: (array zero-terminated=1): #NULL-terminated array of strings.
 * @lookfor: String to look for in @values.
 *
 * Returns: #TRUE if @lookfor is in @values.
 */
gboolean CacheUtilStringArrayContains(const gchar **values,
                                      const gchar *lookfor) {
  if (!values || !lookfor)
    return FALSE;

  for (guint i = 0; values[i]; i++) {
    if (g_strcmp0(values[i], lookfor) == 0) {
      return TRUE;
    }
  }
  return FALSE;
}


/**
 * CacheUtilCheckDuration:
 * @check_date: Date that may or may not fall inside @duration.
 * @duration: Timespan for @check_date to fall in.
 * @start_date: Start of @duration.
 *
 * Returns: #TRUE if @start_date <= @check_date <= @start_date + @duration.
 */
gboolean CacheUtilCheckDuration(GDateTime *check_date, GTimeSpan duration,
                                GDateTime *start_date) {
  GTimeSpan date_diff = g_date_time_difference(check_date, start_date);
  if (date_diff >= 0 && date_diff <= duration) {
    return TRUE;
  } else {
    return FALSE;
  }
}


/**
 * CacheUtilGlob:
 * @patten: See pattern argument of glob().
 *
 * Returns: (array zero-terminated=1)(allow-none): Array of file names matching
 * the pattern, or #NULL if an unreadable directory was found.
 */
gchar **CacheUtilGlob(const gchar *pattern) {
  glob_t glob_result = {0, NULL, 0};
  gchar **result = NULL;

  switch (glob(pattern, GLOB_BRACE | GLOB_ERR, NULL, &glob_result)) {
    case 0:
      break;
    case GLOB_NOMATCH:
      return g_new0(char *, 1); // Zero-length array of strings.
    case GLOB_ABORTED:
      return NULL; // Error reading directory.
    case GLOB_NOSPACE:
      g_error("glob() ran out of memory");
    default:
      g_error("glob() returned unexpected error");
  }

  result = g_strdupv(glob_result.gl_pathv);
  globfree(&glob_result);
  return result;
}

GQuark _UtilErrorQuark() {
  return g_quark_from_string("util-error-quark");
}
