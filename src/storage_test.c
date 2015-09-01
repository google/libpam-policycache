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

#include "storage.h"
#include "test.h"


void TestPutAndGetEntry() {
  CacheTestInitFiles();

  CacheStorage *storage = CacheStorageNew("/mock");
  g_assert(storage);

  CacheEntry *entry_orig = CacheEntryNew();
  g_assert(entry_orig);
  entry_orig->algorithm = CACHE_ENTRY_ALGORITHM_SHA256;
  entry_orig->tries = 5;

  GError *error = NULL;
  g_assert(CacheStoragePutEntry(storage, "testuser", entry_orig, &error));
  g_assert_no_error(error);

  CacheEntry *entry_copy = CacheStorageGetEntry(storage, "testuser", &error);
  g_assert_no_error(error);
  g_assert(entry_copy);

  g_assert_cmpint(CACHE_ENTRY_ALGORITHM_SHA256, ==, entry_copy->algorithm);
  g_assert_cmpint(5, ==, entry_copy->tries);

  CacheEntryUnref(entry_copy);
  CacheEntryUnref(entry_orig);
  CacheStorageUnref(storage);
}


void TestGetMissingEntry() {
  CacheTestInitFiles();

  CacheStorage *storage = CacheStorageNew("/mock");
  g_assert(storage);

  GError *error = NULL;
  CacheEntry *entry = CacheStorageGetEntry(storage, "testuser", &error);
  g_assert(!entry);
  g_assert_error(error, CACHE_STORAGE_ERROR, CACHE_STORAGE_FILE_ERROR);

  g_error_free(error);
  CacheStorageUnref(storage);
}


void TestGetInvalidUsername() {
  CacheTestInitFiles();

  CacheStorage *storage = CacheStorageNew("/mock");
  g_assert(storage);

  GError *error = NULL;
  CacheEntry *entry = CacheStorageGetEntry(storage, "../testuser", &error);
  g_assert(!entry);
  g_assert_error(error, CACHE_STORAGE_ERROR, CACHE_STORAGE_USERNAME_ERROR);

  g_error_free(error);
  CacheStorageUnref(storage);
}


int main(int argc, char **argv) {
  CacheTestInit();
  CacheTestInitUsersAndGroups();
  g_test_init(&argc, &argv, NULL);
  g_test_add_func(
      "/storage_test/TestPutAndGetEntry", TestPutAndGetEntry);
  g_test_add_func(
      "/storage_test/TestGetMissingEntry", TestGetMissingEntry);
  g_test_add_func(
      "/storage_test/TestGetInvalidUsername", TestGetInvalidUsername);
  return g_test_run();
}
