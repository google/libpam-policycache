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

#include "policy.h"
#include "test.h"


void TestSetValue() {
  CachePolicy *policy = CachePolicyNew();
  GError *error = NULL;

  g_assert_cmpint(0, ==, policy->max_tries);
  g_assert(CachePolicySetValue(policy, "tries", "5", &error));
  g_assert_no_error(error);
  g_assert_cmpint(5, ==, policy->max_tries);

  g_assert(!CachePolicySetValue(policy, "tries", "nope", &error));
  g_assert_error(error, CACHE_POLICY_ERROR, CACHE_POLICY_INVALID_VALUE_ERROR);
  g_assert_cmpint(5, ==, policy->max_tries);
  g_error_free(error);
  error = NULL;

  g_assert_cmpint(0, ==, policy->refresh_before);
  g_assert(CachePolicySetValue(policy, "refresh", "2d", &error));
  g_assert_no_error(error);
  g_assert_cmpint(2*G_TIME_SPAN_DAY, ==, policy->refresh_before);

  g_assert(!CachePolicySetValue(policy, "refresh", "5days", &error));
  g_assert_error(error, CACHE_POLICY_ERROR, CACHE_POLICY_INVALID_VALUE_ERROR);
  g_assert_cmpint(2*G_TIME_SPAN_DAY, ==, policy->refresh_before);
  g_error_free(error);
  error = NULL;

  g_assert_cmpint(0, ==, policy->renew_after);
  g_assert(CachePolicySetValue(policy, "renew", "1w", &error));
  g_assert_no_error(error);
  g_assert_cmpint(7*G_TIME_SPAN_DAY, ==, policy->renew_after);

  g_assert_cmpint(0, ==, policy->expire_after);
  g_assert(CachePolicySetValue(policy, "expire", "3w", &error));
  g_assert_no_error(error);
  g_assert_cmpint(3*7*G_TIME_SPAN_DAY, ==, policy->expire_after);

  g_assert(!CachePolicySetValue(policy, "nope", "1", &error));
  g_assert_error(error, CACHE_POLICY_ERROR, CACHE_POLICY_UNKNOWN_KEY_ERROR);
  g_error_free(error);

  CachePolicyUnref(policy);
}


void TestNewForUser() {
  gchar *policy1_path = CacheTestGetDataPath("policy1.conf");
  gchar *policy2_path = CacheTestGetDataPath("policy2.conf");
  const gchar *policy_paths [] = {policy1_path, policy2_path, NULL};
  GError *error = NULL;
  CachePolicy *policy = NULL;

  policy = CachePolicyNewForUser("janedoe", policy_paths, &error);
  g_assert_no_error(error);
  g_assert(policy);
  g_assert_cmpint(5, ==, policy->max_tries);
  CachePolicyUnref(policy);

  policy = CachePolicyNewForUser("johndoe", policy_paths, &error);
  g_assert_no_error(error);
  g_assert(policy);
  g_assert_cmpint(0, ==, policy->max_tries);
  CachePolicyUnref(policy);

  policy = CachePolicyNewForUser("nope", policy_paths, &error);
  g_assert(!policy);
  g_assert_error(error, CACHE_POLICY_ERROR, CACHE_POLICY_UNKNOWN_USER_ERROR);
  g_error_free(error);

  g_free(policy1_path);
  g_free(policy2_path);
}


void TestCheckEntry() {
  GDateTime *now = g_date_time_new_now_utc();
  GDateTime *one_hour_ago = g_date_time_add_hours(now, -1);
  GDateTime *over_1w_ago = g_date_time_add_weeks(one_hour_ago, -1);
  GDateTime *over_2w_ago = g_date_time_add_weeks(one_hour_ago, -2);
  GDateTime *over_3w_ago = g_date_time_add_weeks(one_hour_ago, -3);

  CachePolicy *policy = CachePolicyNew();
  CacheEntry *entry = CacheEntryNew();
  GError *error = NULL;

  // Any entry works with an empty policy.
  entry->tries = 4;
  entry->last_verified = over_3w_ago;
  entry->last_used = over_3w_ago;
  g_assert(CachePolicyCheckEntry(policy, entry, now, &error));
  g_assert_no_error(error);

  // Try against a policy with all fields set from now on.
  CachePolicySetValue(policy, "tries", "3", NULL);
  CachePolicySetValue(policy, "refresh", "1w", NULL);
  CachePolicySetValue(policy, "renew", "2w", NULL);
  CachePolicySetValue(policy, "expire", "3w", NULL);

  entry->tries = 3;
  entry->last_verified = over_2w_ago;
  entry->last_used = one_hour_ago;
  g_assert(CachePolicyCheckEntry(policy, entry, now, &error));
  g_assert_no_error(error);

  entry->last_verified = over_2w_ago;
  entry->last_used = over_1w_ago;
  g_assert(!CachePolicyCheckEntry(policy, entry, now, &error));
  g_assert_error(error, CACHE_POLICY_ERROR, CACHE_POLICY_ENTRY_EXPIRED_ERROR);
  g_error_free(error);
  error = NULL;

  entry->last_verified = over_3w_ago;
  entry->last_used = one_hour_ago;
  g_assert(!CachePolicyCheckEntry(policy, entry, now, &error));
  g_assert_error(error, CACHE_POLICY_ERROR, CACHE_POLICY_ENTRY_EXPIRED_ERROR);
  g_error_free(error);
  error = NULL;

  entry->tries = 4;
  entry->last_verified = one_hour_ago;
  entry->last_used = one_hour_ago;
  g_assert(!CachePolicyCheckEntry(policy, entry, now, &error));
  g_assert_error(error, CACHE_POLICY_ERROR,
                 CACHE_POLICY_MAX_TRIES_EXCEEDED_ERROR);
  g_error_free(error);
  error = NULL;

  entry->last_verified = NULL;
  entry->last_used = NULL;
  CacheEntryUnref(entry);
  CachePolicyUnref(policy);
  g_date_time_unref(now);
  g_date_time_unref(one_hour_ago);
  g_date_time_unref(over_1w_ago);
  g_date_time_unref(over_2w_ago);
  g_date_time_unref(over_3w_ago);
}


void TestShouldRenew() {
  GDateTime *now = g_date_time_new_now_utc();
  GDateTime *one_hour_ago = g_date_time_add_hours(now, -1);
  GDateTime *over_1w_ago = g_date_time_add_weeks(one_hour_ago, -1);
  CachePolicy *policy = CachePolicyNew();
  CacheEntry *entry = CacheEntryNew();

  CachePolicySetValue(policy, "renew", "1w", NULL);

  entry->last_verified = one_hour_ago;
  g_assert(!CachePolicyShouldRenew(policy, entry, now));

  entry->last_verified = over_1w_ago;
  g_assert(CachePolicyShouldRenew(policy, entry, now));

  entry->last_verified = NULL;
  CacheEntryUnref(entry);
  CachePolicyUnref(policy);
  g_date_time_unref(now);
  g_date_time_unref(one_hour_ago);
  g_date_time_unref(over_1w_ago);
}


int main(int argc, char **argv) {
  CacheTestInit();
  CacheTestInitUsersAndGroups();
  g_test_init(&argc, &argv, NULL);
  g_test_add_func("/policy_test/TestSetValue", TestSetValue);
  g_test_add_func("/policy_test/TestNewForUser", TestNewForUser);
  g_test_add_func("/policy_test/TestCheckEntry", TestCheckEntry);
  g_test_add_func("/policy_test/TestShouldRenew", TestShouldRenew);
  return g_test_run();
}
