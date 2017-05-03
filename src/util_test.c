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

#include "test.h"
#include "util.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static guint8 expected_password_hash [] = {
  0x51, 0xcb, 0x22, 0xe1, 0x65, 0x19, 0x78, 0x32, 0x09, 0x14,
  0x56, 0xa2, 0x70, 0x8a, 0x0b, 0xd9, 0xe7, 0x0e, 0x09, 0x35,
};


void TestDatetimeToString() {
  GDateTime *value = g_date_time_new_utc(2001, 2, 3, 14, 25, 36);
  const char *expect = "2001-02-03T14:25:36Z";
  gchar *result = CacheUtilDatetimeToString(value);
  g_assert_cmpstr(expect, ==, result);
  g_free(result);
  g_date_time_unref(value);
}


void TestDatetimeFromString() {
  GDateTime *expect = g_date_time_new_utc(2001, 2, 3, 14, 25, 36);
  GDateTime *result = NULL;
  g_assert(CacheUtilDatetimeFromString("2001-02-03T14:25:36Z", &result));
  g_assert(g_date_time_equal(expect, result));

  g_assert(!CacheUtilDatetimeFromString("", &result));
  g_assert(g_date_time_equal(expect, result)); // result must be unmodified.

  g_assert(!CacheUtilDatetimeFromString("nope", &result));
  g_assert(g_date_time_equal(expect, result));

  g_date_time_unref(result);
  g_date_time_unref(expect);
}


void TestHashalgToString() {
  const gchar *result = CacheUtilHashalgToString(G_CHECKSUM_SHA1);
  g_assert_cmpstr("SHA1", ==, result);

  result = CacheUtilHashalgToString(G_CHECKSUM_SHA256);
  g_assert_cmpstr("SHA256", ==, result);

  result = CacheUtilHashalgToString(-1);
  g_assert_cmpstr(NULL, ==, result);
}


void TestHashalgFromString() {
  GChecksumType result = -1;

  g_assert(CacheUtilHashalgFromString("SHA1", &result));
  g_assert_cmpint(G_CHECKSUM_SHA1, ==, result);

  g_assert(CacheUtilHashalgFromString("SHA256", &result));
  g_assert_cmpint(G_CHECKSUM_SHA256, ==, result);

  g_assert(!CacheUtilHashalgFromString("", &result));
  g_assert_cmpint(G_CHECKSUM_SHA256, ==, result);  // result must be unmodified.

  g_assert(!CacheUtilHashalgFromString("SHA", &result));
  g_assert_cmpint(G_CHECKSUM_SHA256, ==, result);
}



void TestCacheUtilReadShadowFile() { 
  GError *error = NULL;
 
  gchar *example_hash = (
      "$6$1234567890123456$HsVhUUvQnfhyEQ6OIZAWrigLa0qX29Su.3l8G4BBqgRfx9fVAIG9bVcGpOnI0r.vTSsJ3hOVMFCovyIbtpAc81");
  GBytes* gbytes_example_hash = g_bytes_new(example_hash, strlen(example_hash));
  gchar *shadowpath = CacheTestGetDataPath("shadow"); 
 
  // Test for a successful read. 
  GBytes* actual_hash = CacheUtilReadShadowFile(shadowpath, "johndoe", &error);
  g_assert_no_error(error);
  g_assert(g_bytes_equal(gbytes_example_hash, actual_hash));
  
  // Test for a nonexistent user.
  GBytes* no_hash = CacheUtilReadShadowFile(shadowpath, "noone", &error);
  g_assert_error(error, UTIL_ERROR, UTIL_ERROR_NO_HASH);
  g_assert(no_hash == NULL);
  g_error_free(error);
 
  error = NULL; 
  // Test for a nonexistent shadow file.
  GBytes* no_file = CacheUtilReadShadowFile("/etc/shadows", "johndoe", &error);
  g_assert_error(error, UTIL_ERROR, UTIL_ERROR_NO_OPEN_FILE);
  g_assert(no_file == NULL); 
  g_error_free(error);
}



void TestBytesToString() {
  GBytes *value = g_bytes_new_static("\x01\x23\x45\x67\x89\xAB", 6);
  gchar *result = CacheUtilBytesToString(value);
  g_assert_cmpstr("0123456789AB", ==, result);
  g_free(result);
  g_bytes_unref(value);
}


void TestBytesFromString() {
  GBytes *result = NULL;
  GBytes *expect = g_bytes_new_static("\xAB\xCD\xEF", 3);
  GBytes *expect_empty = g_bytes_new_static("", 0);

  g_assert(CacheUtilBytesFromString("ABCDEF", &result));
  g_assert(g_bytes_equal(expect, result));

  g_assert(!CacheUtilBytesFromString("ABCDE", &result));
  g_assert(g_bytes_equal(expect, result));  // result must be unmodified.

  g_assert(!CacheUtilBytesFromString("ABCDE", &result));
  g_assert(g_bytes_equal(expect, result));

  g_bytes_unref(result);
  result = NULL;

  g_assert(CacheUtilBytesFromString("", &result));
  g_assert(g_bytes_equal(expect_empty, result));
  g_bytes_unref(result);

  g_bytes_unref(expect);
  g_bytes_unref(expect_empty);
}


void TestHashPassword() {
  GBytes *salt = g_bytes_new_static("\x01\x34\x56\x78", 4);
  const gchar *password = "supersecret";
  GBytes *result = CacheUtilHashPassword(G_CHECKSUM_SHA1, salt, password);
  GBytes *expect = g_bytes_new_static(expected_password_hash, 20);
  g_assert(g_bytes_compare(result, expect) == 0);
  g_bytes_unref(salt);
  g_bytes_unref(result);
  g_bytes_unref(expect);
}


void TestRandomBytes() {
  // g_rand* functions are always stable when given the same seed, even
  // across architectures and versions of glib.
  g_random_set_seed(0);
  GBytes *expect = g_bytes_new_static("\xAC\x0A\x7F\x8C\x2F\xAA", 6);

  GBytes *result = CacheUtilRandomBytes(6);
  g_assert(g_bytes_compare(result, expect) == 0);

  GBytes *result2 = CacheUtilRandomBytes(6);
  g_assert(g_bytes_compare(result2, expect) != 0);

  g_bytes_unref(result);
  g_bytes_unref(result2);
  g_bytes_unref(expect);
}


void TestGetGroupsForUser() {
  gchar **result = NULL;
  gchar *expect_for_jane [] = {"janedoe", "everyone", NULL};
  gchar *expect_for_john [] = {"johndoe", "everyone", NULL};

  result = CacheUtilGetGroupsForUser("janedoe");
  g_assert(result);
  for (guint i = 0; expect_for_jane[i] || result[i]; i++)
    g_assert_cmpstr(expect_for_jane[i], ==, result[i]);
  g_strfreev(result);

  result = CacheUtilGetGroupsForUser("johndoe");
  g_assert(result);
  for (guint i = 0; expect_for_john[i] || result[i]; i++)
    g_assert_cmpstr(expect_for_john[i], ==, result[i]);
  g_strfreev(result);

  result = CacheUtilGetGroupsForUser("popularuser");
  g_assert(result);
  g_assert_cmpint(258, ==, g_strv_length(result));
  g_assert_cmpstr(result[0], ==, "popularuser");
  g_assert_cmpstr(result[1], ==, "everyone");
  g_assert_cmpstr(result[2], ==, "othergroup0");
  g_assert_cmpstr(result[257], ==, "othergroup255");
  g_strfreev(result);

  result = CacheUtilGetGroupsForUser("nope");
  g_assert(!result);
}


void TestTimespanFromString() {
  GTimeSpan value = 1;

  g_assert(CacheUtilTimespanFromString("3h", &value));
  g_assert_cmpint(3*G_TIME_SPAN_HOUR, ==, value);

  g_assert(CacheUtilTimespanFromString("5d", &value));
  g_assert_cmpint(5*G_TIME_SPAN_DAY, ==, value);

  g_assert(CacheUtilTimespanFromString("1w", &value));
  g_assert_cmpint(7*G_TIME_SPAN_DAY, ==, value);

  g_assert(CacheUtilTimespanFromString("-1w", &value));
  g_assert_cmpint(-7*G_TIME_SPAN_DAY, ==, value);

  g_assert(!CacheUtilTimespanFromString("4", &value));
  g_assert_cmpint(-7*G_TIME_SPAN_DAY, ==, value);

  g_assert(!CacheUtilTimespanFromString("1week", &value));
  g_assert_cmpint(-7*G_TIME_SPAN_DAY, ==, value);

  g_assert(!CacheUtilTimespanFromString("nope", &value));
  g_assert_cmpint(-7*G_TIME_SPAN_DAY, ==, value);

  g_assert(!CacheUtilTimespanFromString("", &value));
  g_assert_cmpint(-7*G_TIME_SPAN_DAY, ==, value);
}


void TestSplitString() {
  gchar *left = NULL;
  gchar *right = NULL;

  g_assert(CacheUtilSplitString("foo:bar", ":", &left, &right));
  g_assert_cmpstr("foo", ==, left);
  g_assert_cmpstr("bar", ==, right);

  g_assert(!CacheUtilSplitString("nope", ":", &left, &right));
  g_assert_cmpstr("foo", ==, left);
  g_assert_cmpstr("bar", ==, right);

  g_free(left);
  g_free(right);
}


void TestStringArrayContains() {
  const gchar *test_array [] = {"foo", "bar", "baz", NULL};
  g_assert(CacheUtilStringArrayContains(test_array, "baz"));
  g_assert(CacheUtilStringArrayContains(test_array, "bar"));
  g_assert(CacheUtilStringArrayContains(test_array, "foo"));
  g_assert(!CacheUtilStringArrayContains(test_array, "nope"));
}


void TestCheckDuration() {
  GDateTime *start_date = g_date_time_new_now_utc();
  GDateTime *one_second = g_date_time_add_seconds(start_date, 1);
  GDateTime *one_second_ago = g_date_time_add_seconds(start_date, -1);
  GDateTime *one_hour = g_date_time_add_hours(start_date, 1);
  GDateTime *over_one_hour = g_date_time_add_seconds(one_hour, 1);

  g_assert(CacheUtilCheckDuration(start_date, G_TIME_SPAN_HOUR, start_date));
  g_assert(CacheUtilCheckDuration(one_second, G_TIME_SPAN_HOUR, start_date));
  g_assert(CacheUtilCheckDuration(one_hour, G_TIME_SPAN_HOUR, start_date));

  g_assert(
      !CacheUtilCheckDuration(one_second_ago, G_TIME_SPAN_HOUR, start_date));
  g_assert(
      !CacheUtilCheckDuration(over_one_hour, G_TIME_SPAN_HOUR, start_date));

  g_date_time_unref(start_date);
  g_date_time_unref(one_second);
  g_date_time_unref(one_second_ago);
  g_date_time_unref(one_hour);
  g_date_time_unref(over_one_hour);
}


void TestGlob() {
  gchar *pattern = CacheTestGetDataPath("policy*.conf");
  gchar *expected_path1 = CacheTestGetDataPath("policy1.conf");
  gchar *expected_path2 = CacheTestGetDataPath("policy2.conf");

  gchar **paths = CacheUtilGlob(pattern);
  g_assert_cmpstr(expected_path1, ==, paths[0]);
  g_assert_cmpstr(expected_path2, ==, paths[1]);
  g_assert_cmpstr(NULL, ==, paths[2]);

  g_free(pattern);
  g_free(expected_path1);
  g_free(expected_path2);
  g_strfreev(paths);
}


int main(int argc, char **argv) {
  CacheTestInit();
  CacheTestInitUsersAndGroups();
  g_test_init(&argc, &argv, NULL);

  g_test_add_func(
      "/util_test/TestDatetimeToString", TestDatetimeToString);
  g_test_add_func(
      "/util_test/TestDatetimeFromString", TestDatetimeFromString);
 
  g_test_add_func(
      "/util_test/TestCacheUtilReadShadowFile", TestCacheUtilReadShadowFile);
 
  g_test_add_func(
      "/util_test/TestHashalgToString", TestHashalgToString);
  g_test_add_func(
      "/util_test/TestHashalgFromString", TestHashalgFromString);

  g_test_add_func(
      "/util_test/TestBytesToString", TestBytesToString);
  g_test_add_func(
      "/util_test/TestBytesFromString", TestBytesFromString);

  g_test_add_func(
      "/util_test/TestHashPassword", TestHashPassword);
  g_test_add_func(
      "/util_test/TestRandomBytes", TestRandomBytes);
  g_test_add_func(
      "/util_test/TestGetGroupsForUser", TestGetGroupsForUser);
  g_test_add_func(
      "/util_test/TestTimespanFromString", TestTimespanFromString);
  g_test_add_func(
      "/util_test/TestSplitString", TestSplitString);
  g_test_add_func(
      "/util_test/TestStringArrayContains", TestStringArrayContains);
  g_test_add_func(
      "/util_test/TestCheckDuration", TestCheckDuration);
  g_test_add_func(
      "/util_test/TestGlob", TestGlob);

  return g_test_run();
}

