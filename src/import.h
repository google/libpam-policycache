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


#ifndef CACHE_IMPORT_H_
#define CACHE_IMPORT_H_

#include <glib.h>

#define CACHE_IMPORT_ERROR _CacheImportErrorQuark()

typedef enum {
  CACHE_IMPORT_ERROR_STORAGE_FAIL,
} CacheImportError;


gboolean CacheImport(const char *shadow_path, const char *storage_path, const char *username, GError **error);

GQuark _CacheImportErrorQuark();

#endif
