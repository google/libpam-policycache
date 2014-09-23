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
#include <stdarg.h>
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

static gchar **mock_helper_expected_messages = NULL;
static gchar **mock_helper_response_messages = NULL;

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
  } else if (g_hash_table_contains(self->items, GINT_TO_POINTER(item_type))) {
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


int __wrap_pam_get_user(MockPamHandle *self, const char **username,
                        const char *prompt) {
  g_assert(username);
  g_assert(!prompt);
  g_assert_cmpint(__wrap_pam_get_item(self, PAM_USER, (const void**) username),
                  ==, PAM_SUCCESS);
  g_assert(*username);
  return PAM_SUCCESS;
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


void __wrap_pam_syslog(MockPamHandle *self, gint priority, const gchar *format,
                       ...) {
  va_list args;
  va_start(args, format);
  gchar *message = g_strdup_vprintf(format, args);
  va_end(args);

  g_test_message("pam syslog at level %d: %s", priority, message);
  g_free(message);
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


int __wrap_pam_setcred(MockPamHandle *self, int flags) {
  g_assert(self);
  g_assert(flags == PAM_REINITIALIZE_CRED);
  return PAM_SUCCESS;
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


void EscalateTestSetMockHelperMessages(gchar **expected_messages,
                                       gchar **response_messages) {
  g_strfreev(mock_helper_expected_messages);
  g_strfreev(mock_helper_response_messages);
  mock_helper_expected_messages = g_strdupv(expected_messages);
  mock_helper_response_messages = g_strdupv(response_messages);
}


static int EscalateTestMockHelperProcess(int stdin_fd, int stdout_fd) {
  GIOChannel *stdin_stream = g_io_channel_unix_new(stdin_fd);
  GIOChannel *stdout_stream = g_io_channel_unix_new(stdout_fd);
  GError *error = NULL;
  gboolean success = FALSE;

  g_assert(mock_helper_expected_messages);
  g_assert(mock_helper_response_messages);

  for (guint i = 0; i < g_strv_length(mock_helper_expected_messages); i++) {
    EscalateMessage *expected = NULL;
    EscalateMessage *message = NULL;
    EscalateMessage *response = NULL;

    expected = EscalateMessageLoad(mock_helper_expected_messages[i], &error);
    g_assert_no_error(error);
    g_assert(expected);

    message = EscalateMessageRead(stdin_stream, &error);
    g_assert_no_error(error);
    g_assert(message);

    if (mock_helper_response_messages[i]) {
      response = EscalateMessageLoad(mock_helper_response_messages[i], &error);
      g_assert_no_error(error);
      g_assert(response);
    }

    g_assert_cmpint(expected->type, ==, message->type);
    if (!g_variant_equal(expected->values, message->values)) {
      gchar *variant_str = g_variant_print(expected->values, FALSE);
      g_message("Expected: %s", variant_str);
      g_free(variant_str);
      variant_str = g_variant_print(message->values, FALSE);
      g_message("Got: %s", variant_str);
      g_free(variant_str);
      g_error("Message values didn't match what was expected");
    }

    if (response) {
      success = EscalateMessageWrite(response, stdout_stream, &error);
      g_assert_no_error(error);
      g_assert(success);
      EscalateMessageUnref(response);
    }

    EscalateMessageUnref(expected);
    EscalateMessageUnref(message);
  }

  g_io_channel_shutdown(stdin_stream, FALSE, NULL);
  g_io_channel_shutdown(stdout_stream, FALSE, NULL);
  g_io_channel_unref(stdin_stream);
  g_io_channel_unref(stdout_stream);
  return 0;
}


gboolean __wrap_g_spawn_async_with_pipes(const gchar *working_directory,
                                         gchar **argv,
                                         gchar **envp,
                                         GSpawnFlags flags,
                                         GSpawnChildSetupFunc child_setup,
                                         gpointer user_data,
                                         GPid *child_pid,
                                         gint *standard_input,
                                         gint *standard_output,
                                         gint *standard_error,
                                         GError **error) {
  int standard_input_fds [2] = { 0, 0 };
  int standard_output_fds [2] = { 0, 0 };
  pid_t pid = 0;

  g_assert_cmpstr("/", ==, working_directory);
  g_assert(argv);
  g_assert_cmpstr("/usr/bin/pam-escalate-helper", ==, argv[0]);
  g_assert_cmpstr(NULL, ==, argv[1]);
  g_assert(!envp);
  g_assert_cmpint(0, ==, flags);
  g_assert(!child_setup);
  g_assert(!user_data);
  g_assert(child_pid);
  g_assert(standard_input);
  g_assert(standard_output);
  g_assert(!standard_error);

  g_assert(g_unix_open_pipe(standard_input_fds, 0, NULL));
  g_assert(g_unix_open_pipe(standard_output_fds, 0, NULL));

  pid = fork();
  if (pid) {
    close(standard_input_fds[0]);
    close(standard_output_fds[1]);
    *child_pid = pid;
    *standard_input = standard_input_fds[1];
    *standard_output = standard_output_fds[0];
    return TRUE;
  } else {
    close(standard_input_fds[1]);
    close(standard_output_fds[0]);
    exit(EscalateTestMockHelperProcess(standard_input_fds[0],
                                       standard_output_fds[1]));
  }
}
