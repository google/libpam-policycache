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
#include "test.h"
#include "util.h"

const gchar *example_entry_v1 = (
    "{'version': <1>, 'tries': <0>, 'algorithm': <'SHA256'>, "
    "'salt': <'0B8BAA809CDCA339910EE8F6F9FE22A5'>, "
    "'hash':"
    " <'14BABCBC943B302EFDCC137419F7D3FB736602D77CF42975A6778A5B7F2D63CD'>, "
    "'last_verified': <'2014-03-28T23:14:21Z'>, "
    "'last_used': <'2014-03-28T23:14:21Z'>, "
    "'last_tried': <'2014-03-28T23:14:21Z'>}"
    );

const gchar *example_entry_v2 = (
    "{'version': <2>, 'tries': <0>, 'algorithm': <'SHA256'>, "
    "'args': <{'salt': <'0B8BAA809CDCA339910EE8F6F9FE22A5'>}>, "
    "'hash':"
    " <'14BABCBC943B302EFDCC137419F7D3FB736602D77CF42975A6778A5B7F2D63CD'>, "
    "'last_verified': <'2014-03-28T23:14:21Z'>, "
    "'last_used': <'2014-03-28T23:14:21Z'>, "
    "'last_tried': <'2014-03-28T23:14:21Z'>}"
    );

const gchar *example_salt = "0B8BAA809CDCA339910EE8F6F9FE22A5";
const gchar *example_hash = (
    "14BABCBC943B302EFDCC137419F7D3FB736602D77CF42975A6778A5B7F2D63CD");
const gchar *example_time = "2014-03-28T23:14:21Z";


void TestPasswordSetAndVerify() {
  GError *error = NULL;
  CacheEntry *entry = CacheEntryNew();
  g_assert(entry);

  // Set the password then make sure "last_*" and "tries" were updated.
  entry->tries = 5;
  g_assert(CacheEntryPasswordSet(entry, "supersecret", &error));
  g_assert_no_error(error);
  g_assert_cmpint(0, ==, entry->tries);
  g_assert(g_date_time_equal(entry->last_verified, entry->last_used));
  g_assert(g_date_time_equal(entry->last_used, entry->last_tried));

  CacheTestAddMockTime(G_TIME_SPAN_HOUR);

  // Try the same password. Make sure it updates "last_used" and "last_tried".
  g_assert(
      CacheEntryPasswordValidate(entry, "supersecret", &error));
  g_assert_no_error(error);
  g_assert_cmpint(0, ==, entry->tries);
  g_assert(!g_date_time_equal(entry->last_verified, entry->last_used));
  g_assert(g_date_time_equal(entry->last_used, entry->last_tried));

  CacheTestAddMockTime(G_TIME_SPAN_HOUR);

  // Try a bad password. Make sure it updates "tries" and "last_tried".
  g_assert(!CacheEntryPasswordValidate(entry, "superfail", &error));
  g_assert_error(error, CACHE_ENTRY_ERROR, CACHE_ENTRY_PASSWORD_ERROR);
  g_assert_cmpint(1, ==, entry->tries);
  g_assert(!g_date_time_equal(entry->last_verified, entry->last_used));
  g_assert(!g_date_time_equal(entry->last_used, entry->last_tried));

  CacheEntryUnref(entry);
  g_error_free(error);
}


void TestUnserialize(const gchar *data) {
  // Parse the entry in "example_entry".
  GError *error = NULL;
  CacheEntry *entry = CacheEntryUnserialize(data, &error);
  g_assert(entry);
  g_assert_no_error(error);

  // Check basic types.
  g_assert_cmpint(0, ==, entry->tries);
  g_assert_cmpint(CACHE_ENTRY_ALGORITHM_SHA256, ==, entry->algorithm);

  // Make sure all "last_*" attributes match "example_date".
  GDateTime *expected_time = NULL;
  CacheUtilDatetimeFromString(example_time, &expected_time);
  g_assert(g_date_time_equal(expected_time, entry->last_verified));
  g_assert(g_date_time_equal(expected_time, entry->last_used));
  g_assert(g_date_time_equal(expected_time, entry->last_tried));

  // Make sure the entry's salt matches "example_salt".
  GBytes *expect_salt = NULL;
  CacheUtilBytesFromString(example_salt, &expect_salt);
  g_assert(entry->args.basic_salt);
  g_assert(g_bytes_equal(expect_salt, entry->args.basic_salt));

  // Make sure the entry's hash matches "example_hash".
  GBytes *expect_hash = NULL;
  CacheUtilBytesFromString(example_hash, &expect_hash);
  g_assert(entry->hash);
  g_assert(g_bytes_equal(expect_hash, entry->hash));

  // Make sure validate(...) actually works. This modifies dates in the entry.
  g_assert(CacheEntryPasswordValidate(entry, "supersecret", &error));
  g_assert_no_error(error);

  g_bytes_unref(expect_hash);
  g_bytes_unref(expect_salt);
  g_date_time_unref(expected_time);
  CacheEntryUnref(entry);
}


void TestUnserializeV1() {
  TestUnserialize(example_entry_v1);
}


void TestUnserializeV2() {
  TestUnserialize(example_entry_v2);
}


void TestUnserializeInvalidString() {
  GError *error = NULL;
  CacheEntry *entry = CacheEntryUnserialize("nope", &error);
  g_assert(!entry);
  g_assert_error(error, CACHE_ENTRY_ERROR, CACHE_ENTRY_PARSE_ERROR);
  g_error_free(error);
}


void TestSerialize() {
  // Create an entry just like "example_entry".
  CacheEntry *entry = CacheEntryNew();
  entry->tries = 0;
  entry->algorithm = CACHE_ENTRY_ALGORITHM_SHA256;
  CacheUtilBytesFromString(example_salt, &entry->args.basic_salt);
  CacheUtilBytesFromString(example_hash, &entry->hash);
  CacheUtilDatetimeFromString(example_time, &entry->last_verified);
  CacheUtilDatetimeFromString(example_time, &entry->last_used);
  CacheUtilDatetimeFromString(example_time, &entry->last_tried);

  // Serialize it and compare the string against the example.
  gchar *result = CacheEntrySerialize(entry);
  g_assert_cmpstr(example_entry_v2, ==, result);

  g_free(result);
  CacheEntryUnref(entry);
}


int main(int argc, char **argv) {
  CacheTestInit();
  g_test_init(&argc, &argv, NULL);
  g_test_add_func(
      "/entry_test/TestPasswordSetAndVerify", TestPasswordSetAndVerify);
  g_test_add_func("/entry_test/TestUnserializeV1", TestUnserializeV1);
  g_test_add_func("/entry_test/TestUnserializeV2", TestUnserializeV2);
  g_test_add_func("/entry_test/TestUnserializeInvalidString", TestUnserializeInvalidString);
  g_test_add_func("/entry_test/TestSerialize", TestSerialize);
  return g_test_run();
}

