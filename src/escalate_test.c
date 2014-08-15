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

#define _GNU_SOURCE

#include "escalate_message.h"
#include "escalate_test.h"

#include <glib-unix.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
  struct pam_conv conversation;
  GHashTable *items;
  GHashTable *env;
} MockPamHandle;

static int basic_pam_items [] = {
  PAM_SERVICE, PAM_USER, PAM_USER_PROMPT, PAM_TTY, PAM_RUSER, PAM_RHOST,
  PAM_AUTHTOK, PAM_OLDAUTHTOK, PAM_XDISPLAY, PAM_AUTHTOK_TYPE
};

static gchar **helper_expected_messages = NULL;
static gchar **helper_response_messages = NULL;

static GPtrArray *mock_authenticate_prompts = NULL;
static int mock_authenticate_result = 0;

static uid_t mock_ruid = 0;
static uid_t mock_euid = 0;
static gid_t mock_rgid = 0;
static gid_t mock_egid = 0;


int __wrap_pam_start(const char *service, const char *username,
                     const struct pam_conv *conv, MockPamHandle **handle) {
  MockPamHandle *self = g_new0(MockPamHandle, 1);
  self->items = g_hash_table_new_full(NULL, NULL, NULL, g_free);
  g_hash_table_insert(self->items, GINT_TO_POINTER(PAM_SERVICE),
                      g_strdup(service));
  g_hash_table_insert(self->items, GINT_TO_POINTER(PAM_USER),
                      g_strdup(username));
  self->env = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
  memcpy(&self->conversation, conv, sizeof(self->conversation));
  *handle = self;
  return PAM_SUCCESS;
}


int __wrap_pam_end(MockPamHandle *self, int pam_status) {
  g_hash_table_destroy(self->items);
  g_hash_table_destroy(self->env);
  g_free(self);
  return PAM_SUCCESS;
}


const char *__wrap_pam_strerror(MockPamHandle *self, int errnum) {
  static gchar result [80];
  g_free(result);
  g_snprintf(result, 80, "mock error message (errnum=%d)", errnum);
  return result;
}


static gboolean EscalateTestIsBasicPamItem(int item_type) {
  for (guint i = 0; i < G_N_ELEMENTS(basic_pam_items); i++) {
    if (basic_pam_items[i] == item_type) {
      return TRUE;
    }
  }
  return FALSE;
}


int __wrap_pam_get_item(const MockPamHandle *self, int item_type,
                        const void **item) {
  g_assert(item);
  if (item_type == PAM_CONV) {
    *item = &self->conversation;
    return PAM_SUCCESS;
  } else if (EscalateTestIsBasicPamItem(item_type)) {
    *item = g_hash_table_lookup(self->items, GINT_TO_POINTER(item_type));
    return PAM_SUCCESS;
  } else {
    return PAM_BAD_ITEM;
  }
}


int __wrap_pam_set_item(MockPamHandle *self, int item_type,
                        const void *item) {
  g_assert(item);
  if (item_type == PAM_CONV) {
    memcpy(&self->conversation, item, sizeof(self->conversation));
    return PAM_SUCCESS;
  } else if (EscalateTestIsBasicPamItem(item_type)) {
    g_hash_table_insert(self->items, GINT_TO_POINTER(item_type),
                        g_strdup((const gchar *) item));
    return PAM_SUCCESS;
  } else {
    return PAM_BAD_ITEM;
  }
}


const char *__wrap_pam_getenv(MockPamHandle *self, const char *name) {
  return (const char *) g_hash_table_lookup(self->env, name);
}


int __wrap_pam_putenv(MockPamHandle *self, const char *name_and_value) {
  gchar **parts = g_strsplit(name_and_value, "=", 2);
  g_assert(parts[0]);
  if (parts[1]) {
    g_hash_table_insert(self->env, g_strdup(parts[0]), g_strdup(parts[1]));
  } else {
    g_hash_table_remove(self->env, parts[0]);
  }
  g_strfreev(parts);
  return PAM_SUCCESS;
}


char **__wrap_pam_getenvlist(MockPamHandle *self) {
  GHashTableIter iter;
  gchar *key = NULL;
  gchar *value = NULL;
  guint i = 0;
  char **result = calloc(g_hash_table_size(self->env) + 1, sizeof(char *));

  g_hash_table_iter_init(&iter, self->env);
  for (; g_hash_table_iter_next(&iter, (void **) &key, (void **) &value); i++) {
    g_assert(key);
    g_assert(value);
    g_assert(asprintf(&result[i], "%s=%s", key, value) > 0);
  }

  result[g_hash_table_size(self->env)] = NULL;
  return result;
}


static EscalateTestPrompt *EscalateTestPromptCopy(EscalateTestPrompt *prompt) {
  EscalateTestPrompt *result = g_new0(EscalateTestPrompt, 1);
  result->type = prompt->type;
  result->message = g_strdup(prompt->message);
  result->expect = g_strdup(prompt->expect);
  return result;
}


static void EscalateTestPromptFree(EscalateTestPrompt *prompt) {
  g_free(prompt->message);
  g_free(prompt->expect);
  g_free(prompt);
}


void EscalateTestMockAuthenticate(EscalateTestPrompt *prompts, int result) {
  g_assert(!mock_authenticate_prompts);
  mock_authenticate_prompts = g_ptr_array_new_with_free_func(
      (GDestroyNotify) EscalateTestPromptFree);
  for (guint i = 0; prompts[i].message; i++) {
    g_ptr_array_add(mock_authenticate_prompts,
                    EscalateTestPromptCopy(&prompts[i]));
  }
  mock_authenticate_result = result;
}


int __wrap_pam_authenticate(MockPamHandle *self, int flags) {
  EscalateTestPrompt *prompt = NULL;
  struct pam_message message;
  const struct pam_message *message_array [] = { &message, NULL };
  struct pam_response *response = NULL;
  int status = 0;
  g_assert_cmpint(0, ==, flags);
  g_assert(self);
  g_assert(self->conversation.conv);
  g_assert(mock_authenticate_prompts);
  for (guint i = 0; i < mock_authenticate_prompts->len; i++) {
    prompt = (EscalateTestPrompt *) mock_authenticate_prompts->pdata[i];
    message.msg_style = prompt->type;
    message.msg = prompt->message;

    status = self->conversation.conv(1, message_array, &response,
                                     self->conversation.appdata_ptr);
    g_assert_cmpint(PAM_SUCCESS, ==, status);
    g_assert_cmpstr(prompt->expect, ==, response[0].resp);

    free(response[0].resp);
    free(response);
  }
  g_ptr_array_free(mock_authenticate_prompts, TRUE);
  mock_authenticate_prompts = NULL;
  return mock_authenticate_result;
}


void EscalateTestSetHelperMessages(gchar **expected_messages,
                                   gchar **response_messages) {
  g_assert_cmpint(g_strv_length(expected_messages), ==,
                  g_strv_length(response_messages));
  helper_expected_messages = g_strdupv(expected_messages);
  helper_response_messages = g_strdupv(response_messages);
}


void EscalateTestSetIds(uid_t ruid, uid_t euid, gid_t rgid, gid_t egid) {
  mock_ruid = ruid;
  mock_euid = euid;
  mock_rgid = rgid;
  mock_egid = egid;
}


uid_t __wrap_getuid() {
  return mock_ruid;
}


uid_t __wrap_geteuid() {
  return mock_euid;
}


gid_t __wrap_getgid() {
  return mock_rgid;
}


gid_t __wrap_getegid() {
  return mock_egid;
}
