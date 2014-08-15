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

#include <sys/wait.h>


/**
 * EscalateSubprocessNew:
 * @path: Full path to helper executable, or #NULL to use the default.
 * @error: (out)(allow-none): Error return location or #NULL.
 *
 * Returns: New #EscalateSubprocess instance wrapping a running helper process.
 */
EscalateSubprocess *EscalateSubprocessNew(const gchar *path, GError **error) {
  GPid child_pid = 0;
  gint child_stdin_fd = 0;
  gint child_stdout_fd = 0;
  EscalateSubprocess *self = NULL;
  const gchar *child_argv [] = { path, NULL };

  if (!child_argv[0])
    child_argv[0] = "/usr/bin/pam-escalate-helper";

  if (!g_spawn_async_with_pipes(NULL, (gchar **) child_argv, NULL, 0, NULL,
                                NULL, &child_pid, &child_stdin_fd,
                                &child_stdout_fd, NULL, error)) {
    return NULL;
  }

  self = g_new0(EscalateSubprocess, 1);
  self->_refcount = 1;
  self->child_pid = child_pid;
  self->child_stdin = g_io_channel_unix_new(child_stdin_fd);
  self->child_stdout = g_io_channel_unix_new(child_stdout_fd);
  return self;
}


void EscalateSubprocessRef(EscalateSubprocess *self) {
  g_assert(self->_refcount > 0);
  self->_refcount++;
}


void EscalateSubprocessUnref(EscalateSubprocess *self) {
  g_assert(self->_refcount > 0);
  self->_refcount--;
  if (self->_refcount)
    return;

  // TODO: Cleanup process.
}


/**
 * EscalateSubprocessSend:
 * @self: Subprocess to send a message to.
 * @message: Message to serialize and write to the process's stdin.
 * @error: (out)(allow-none): Error return location or #NULL.
 *
 * Returns: #TRUE if the message was successfully written.
 */
gboolean EscalateSubprocessSend(EscalateSubprocess *self,
                                EscalateMessage *message, GError **error) {
  return EscalateMessageWrite(message, self->child_stdin, error);
}


/**
 * EscalateSubprocessRecv:
 * @self: Subprocess to receive a message from.
 * @error: (out)(allow-none): Error return location or #NULL.
 *
 * Returns: Message that was read from the process's stdout, or #NULL on error.
 */
EscalateMessage *EscalateSubprocessRecv(EscalateSubprocess *self,
                                        GError **error) {
  return EscalateMessageRead(self->child_stdout, error);
}
