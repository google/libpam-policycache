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

#include "escalate_message.h"
#include "escalate_subprocess.h"


static void TestSendAndRecv() {
  GError *error = NULL;
  EscalateSubprocess *process = NULL;
  EscalateMessage *message = NULL;
  gboolean success = FALSE;
  EscalateMessage *response = NULL;

  process = EscalateSubprocessNew("/bin/cat", &error);
  g_assert_no_error(error);
  g_assert(process);

  message = EscalateMessageNew(ESCALATE_MESSAGE_TYPE_CONV_MESSAGE, 1, "test");
  g_assert(message);

  success = EscalateSubprocessSend(process, message, &error);
  g_assert_no_error(error);
  g_assert(success);

  response = EscalateSubprocessRecv(process, &error);
  g_assert_no_error(error);
  g_assert(response);
  g_assert_cmpint(message->type, ==, response->type);
  g_assert(g_variant_equal(message->values, response->values));

  success = EscalateSubprocessShutdown(process, 1000, &error);
  g_assert_no_error(error);
  g_assert(success);

  EscalateSubprocessUnref(process);
  EscalateMessageUnref(message);
  EscalateMessageUnref(response);
}


static void TestHang() {
  GError *error = NULL;
  EscalateSubprocess *process = NULL;
  GIOChannel *child_stdin = NULL;
  gboolean success = FALSE;

  process = EscalateSubprocessNew("/bin/cat", &error);
  g_assert_no_error(error);
  g_assert(process);

  child_stdin = process->child_stdin;
  process->child_stdin = NULL;

  success = EscalateSubprocessShutdown(process, 1, &error);
  g_assert_error(error, ESCALATE_SUBPROCESS_ERROR,
                 ESCALATE_SUBPROCESS_ERROR_SHUTDOWN_TIMEOUT);
  g_error_free(error);
  g_assert(!success);

  EscalateSubprocessUnref(process);
  g_io_channel_unref(child_stdin);
}


static void TestUnreadMessage() {
  GError *error = NULL;
  EscalateSubprocess *process = NULL;
  EscalateMessage *message = NULL;
  gboolean success = FALSE;

  process = EscalateSubprocessNew("/bin/cat", &error);
  g_assert_no_error(error);
  g_assert(process);

  message = EscalateMessageNew(ESCALATE_MESSAGE_TYPE_CONV_MESSAGE, 1, "test");
  g_assert(message);

  success = EscalateSubprocessSend(process, message, &error);
  g_assert_no_error(error);
  g_assert(success);

  success = EscalateSubprocessShutdown(process, 1000, &error);
  g_assert_error(error, ESCALATE_SUBPROCESS_ERROR,
                 ESCALATE_SUBPROCESS_ERROR_LEFTOVER_STDOUT);
  g_error_free(error);
  g_assert(!success);

  EscalateSubprocessUnref(process);
  EscalateMessageUnref(message);
}


int main(int argc, char **argv) {
  g_test_init(&argc, &argv, NULL);
  g_test_add_func("/escalate_subprocess_test/TestSendAndRecv", TestSendAndRecv);
  g_test_add_func("/escalate_subprocess_test/TestHang", TestHang);
  g_test_add_func("/escalate_subprocess_test/TestUnreadMessage",
                  TestUnreadMessage);
  return g_test_run();
}
