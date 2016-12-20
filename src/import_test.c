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

#include "import.h"
#include "storage.h"
#include <glib.h>
#include <test.h>

void TestCacheImport() {
  CacheTestInitFiles();
  gchar *shadow_path = CacheTestGetDataPath("shadow");

  GError *error = NULL;    
  g_assert(CacheImport(shadow_path, "/mock", "janedoe", &error));
  g_assert_no_error(error);
  
  CacheStorage *storage = CacheStorageNew("/mock");
  CacheEntry *entry = CacheStorageGetEntry(storage, "janedoe", &error);

  g_assert(CacheEntryPasswordValidate(entry, "password", &error));
  
}

int main(int argc, char **argv) {
  CacheTestInit();
  g_test_init(&argc, &argv, NULL);
  g_test_add_func(
      "/import_test/TestCacheImport", TestCacheImport); 
  return g_test_run();
}
