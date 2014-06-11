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

#ifndef CACHE_POLICY_H_
#define CACHE_POLICY_H_

#include <glib.h>

#include "entry.h"

#define CACHE_POLICY_ERROR _CachePolicyErrorQuark()

/**
 * CachePolicy:
 * @refcount: (skip): Number of references to the policy.
 * @max_tries: Maximum number of failed attempts before a #CacheEntry becomes
 * invalid.
 * @refresh_before: Maximum amount of time a #CacheEntry remains valid between
 * successful uses.
 * @renew_after: Time from the last successful validation when other auth
 * mechanisms should be tried, regardless of cache success, so the #CacheEntry
 * doesn't expire.
 * @expire_after: Time from the last successful validation when the #CacheEntry
 * becomes invalid.
 */
typedef struct {
  int refcount;
  guint max_tries;
  GTimeSpan refresh_before;
  GTimeSpan renew_after;
  GTimeSpan expire_after;
} CachePolicy;

/**
 * CachePolicyError:
 * @CACHE_POLICY_UNKNOWN_USER_ERROR: Username not found by getpwnam().
 * @CACHE_POLICY_UNKNOWN_KEY_ERROR: Unknown key found in the policy config.
 * @CACHE_POLICY_INVALID_VALUE_ERROR: Invalid value found in the policy config.
 * @CACHE_POLICY_MAX_TRIES_EXCEEDED_ERROR: Given #CacheEntry can't be used
 * because of too many failed auth attempts.
 * @CACHE_POLICY_ENTRY_EXPIRED_ERROR: Given #CacheEntry expired from lack of use
 * or a lack of validation against another source.
 */
typedef enum {
  CACHE_POLICY_UNKNOWN_USER_ERROR,
  CACHE_POLICY_UNKNOWN_KEY_ERROR,
  CACHE_POLICY_INVALID_VALUE_ERROR,
  CACHE_POLICY_MAX_TRIES_EXCEEDED_ERROR,
  CACHE_POLICY_ENTRY_EXPIRED_ERROR,
} CachePolicyError;

CachePolicy *CachePolicyNew();
CachePolicy *CachePolicyNewFromSection(GKeyFile *key_file, const gchar *section,
                                       GError **error);
CachePolicy *CachePolicyNewForUser(const gchar *username,
                                   gchar **paths,
                                   GError **error);

void CachePolicyRef(CachePolicy *self);
void CachePolicyUnref(CachePolicy *self);

gboolean CachePolicySetValue(CachePolicy *self, const gchar *key,
                             const char *value, GError **error);

gboolean CachePolicyCheckEntry(CachePolicy *self, CacheEntry *entry,
                               GDateTime *now, GError **error);
gboolean CachePolicyShouldRenew(CachePolicy *self, CacheEntry *entry,
                                GDateTime *now);

GQuark _CachePolicyErrorQuark();

#endif
