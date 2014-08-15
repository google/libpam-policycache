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

#include "escalate_helper.h"
#include "escalate_test.h"
#include "test.h"

#include <glib-unix.h>
#include <security/pam_appl.h>


static void CreateHelper(EscalateHelper **helper, GIOChannel **stdin_writer,
                         GIOChannel **stdout_reader) {
  int stdin_fds [2];
  int stdout_fds [2];
  g_assert(g_unix_open_pipe(stdin_fds, 0, NULL));
  g_assert(g_unix_open_pipe(stdout_fds, 0, NULL));

  *helper = EscalateHelperNew(stdin_fds[0], stdout_fds[1]);
  *stdin_writer = g_io_channel_unix_new(stdin_fds[1]);
  *stdout_reader = g_io_channel_unix_new(stdout_fds[0]);

  g_assert(*helper);
}


static void WriteMessage(GIOChannel *channel, const gchar *message_str) {
  GError *error = NULL;
  EscalateMessage *message = EscalateMessageLoad(message_str, &error);
  g_assert_no_error(error);
  g_assert(message);
  gboolean success = EscalateMessageWrite(message, channel, &error);
  g_assert_no_error(error);
  g_assert(success);
  EscalateMessageUnref(message);
}


static void AssertMessage(GIOChannel *channel, const gchar *expected_str) {
  GError *error = NULL;
  EscalateMessage *expected = EscalateMessageLoad(expected_str, &error);
  g_assert_no_error(error);
  g_assert(expected);
  EscalateMessage *message = EscalateMessageRead(channel, &error);
  g_assert_no_error(error);
  g_assert(message);
  g_assert_cmpint(expected->type, ==, message->type);
  g_assert(g_variant_equal(expected->values, message->values));
  EscalateMessageUnref(expected);
  EscalateMessageUnref(message);
}


static gpointer RunHelperThreadFunc(EscalateHelper *helper) {
  GError *error = NULL;
  if (!EscalateHelperHandleStart(helper, &error)) {
    g_print("EscalateHelperHandleStart failed: %s (%s, %d)", error->message,
              g_quark_to_string(error->domain), error->code);
    goto done;
  }
  if (!EscalateHelperDoAction(helper, &error)) {
    g_print("EscalateHelperDoAction failed: %s (%s, %d)", error->message,
              g_quark_to_string(error->domain), error->code);
  }

done:
  g_io_channel_shutdown(helper->reader, FALSE, NULL);
  g_io_channel_shutdown(helper->writer, FALSE, NULL);
  return NULL;
}


static GThread *RunHelperThread(EscalateHelper *helper) {
  GThread *thread = g_thread_new("EscalateHelperThread",
                                 (GThreadFunc) RunHelperThreadFunc, helper);
  g_assert(thread);
  return thread;
}


static void JoinHelperThread(GThread *thread) {
  GError *error = (GError *) g_thread_join(thread);
  g_assert_no_error(error);
}


static EscalateTestPrompt auth_success_prompts [] = {
  { PAM_PROMPT_ECHO_OFF, "Password: ", "testpass" },
  { PAM_TEXT_INFO, "Success!", NULL },
  { 0, NULL, NULL },
};


void TestAuthSuccess() {
  EscalateHelper *helper = NULL;
  GIOChannel *stdin_writer = NULL;
  GIOChannel *stdout_reader = NULL;
  GThread *helper_thread = NULL;

  EscalateTestSetIds(100, 0, 100, 0);
  EscalateTestMockAuthenticate(auth_success_prompts, PAM_SUCCESS);

  CreateHelper(&helper, &stdin_writer, &stdout_reader);
  helper_thread = RunHelperThread(helper);

  WriteMessage(stdin_writer,
               "(1, <(1, 0, 'janedoe', {3: @ms '/dev/pts/9000'})>)");
  AssertMessage(stdout_reader, "(2, <(1, 'Password: ')>)");
  WriteMessage(stdin_writer, "(3, <(@ms 'testpass', 0)>)");
  AssertMessage(stdout_reader, "(2, <(4, 'Success!')>)");
  WriteMessage(stdin_writer, "(3, <(@ms nothing, 0)>)");
  AssertMessage(stdout_reader, "(4, <(0,)>)");

  JoinHelperThread(helper_thread);
  EscalateHelperFree(helper);
  g_io_channel_unref(stdin_writer);
  g_io_channel_unref(stdout_reader);
}


int main(int argc, char **argv) {
  CacheTestInit();
  CacheTestInitUsersAndGroups();
  g_test_init(&argc, &argv, NULL);
  g_test_add_func("/escalate_helper_test/TestAuthSuccess", TestAuthSuccess);
  return g_test_run();
}
