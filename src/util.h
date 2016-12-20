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

#ifndef CACHE_UTIL_H_
#define CACHE_UTIL_H_

#include <glib.h>

#define UTIL_ERROR _UtilErrorQuark()

typedef enum {
  UTIL_ERROR_NO_HASH,
  UTIL_ERROR_NO_OPEN_FILE,
} UtilError;


gchar *CacheUtilDatetimeToString(GDateTime *value);
gboolean CacheUtilDatetimeFromString(const gchar *value, GDateTime **result);

const gchar *CacheUtilHashalgToString(GChecksumType value);
gboolean CacheUtilHashalgFromString(const gchar *value, GChecksumType *result);

GBytes *ReadShadowFile(const gchar *path, const gchar *username, GError **error);

gchar *CacheUtilBytesToString(GBytes *value);
gboolean CacheUtilBytesFromString(const gchar *value, GBytes **result);

GBytes *CacheUtilHashPassword(GChecksumType algorithm, GBytes *salt,
                              const char *password);

GBytes *CacheUtilRandomBytes(gsize size);

gchar **CacheUtilGetGroupsForUser(const gchar *username);

gboolean CacheUtilTimespanFromString(const gchar *value, GTimeSpan *result);

gboolean CacheUtilSplitString(const gchar *value, const gchar *delim,
                              gchar **left, gchar **right);
gboolean CacheUtilStringArrayContains(const gchar **values,
                                      const gchar *lookfor);

gboolean CacheUtilCheckDuration(GDateTime *check_date, GTimeSpan duration,
                                GDateTime *start_date);

gchar **CacheUtilGlob(const gchar *pattern);

GQuark _UtilErrorQuark();

#endif
