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

#include <errno.h>
#include <signal.h>
#include <sys/types.h>
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

  if (!g_spawn_async_with_pipes("/", (gchar **) child_argv, NULL,
                                0, NULL, NULL,
                                &child_pid, &child_stdin_fd, &child_stdout_fd,
                                NULL, error)) {
    return NULL;
  }

  g_assert(child_pid > 0);
  g_assert(child_stdin_fd > 0);
  g_assert(child_stdout_fd > 0);

  self = g_new0(EscalateSubprocess, 1);
  self->_refcount = 1;
  self->child_pid = child_pid;
  self->child_stdin = g_io_channel_unix_new(child_stdin_fd);
  self->child_stdout = g_io_channel_unix_new(child_stdout_fd);
  g_io_channel_set_close_on_unref(self->child_stdin, TRUE);
  g_io_channel_set_close_on_unref(self->child_stdout, TRUE);
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

  if (self->child_stdin)
    g_io_channel_unref(self->child_stdin);
  if (self->child_stdout)
    g_io_channel_unref(self->child_stdout);

  g_free(self);
}


/**
 * EscalateSubprocessShutdown:
 * @self: Subprocess that won't have any more messages sent to it.
 * @timeout_ms: Maximum time in milliseconds to wait for its stdout to close
 * before sending SIGKILL to the process.
 * @error: (out)(allow-none): Error return location or #NULL.
 *
 * Returns: #TRUE if stdout closed and had no more messages, or #FALSE if @error
 * is set and SIGKILL was sent.
 */
gboolean EscalateSubprocessShutdown(EscalateSubprocess *self, guint timeout_ms,
                                    GError **error) {
  GIOChannel *child_stdout = self->child_stdout;
  g_assert(child_stdout);
  GIOStatus status = G_IO_STATUS_ERROR;
  gint64 start_time = g_get_monotonic_time();
  GPollFD poll_fd = {
    g_io_channel_unix_get_fd(child_stdout), G_IO_IN | G_IO_HUP | G_IO_ERR, 0 };
  gchar leftover = '\0';
  gsize leftover_length = 0;
  gboolean result = FALSE;

  g_assert(self->child_pid);

  if (self->child_stdin)
    g_io_channel_unref(self->child_stdin);

  self->child_stdin = NULL;
  self->child_stdout = NULL;

  do {
    status = g_io_channel_set_flags(child_stdout, G_IO_FLAG_NONBLOCK, NULL);
  } while (status == G_IO_STATUS_AGAIN);
  g_assert(status == G_IO_STATUS_NORMAL);

  do {
    // Wait for stdout to be readable.
    gint poll_timeout = timeout_ms - (g_get_monotonic_time() - start_time)/1000;
    gint poll_result = 0;
    if (poll_timeout > 0)
      poll_result = g_poll(&poll_fd, 1, poll_timeout);
    if (poll_result == 0) {
      g_set_error(error, ESCALATE_SUBPROCESS_ERROR,
                  ESCALATE_SUBPROCESS_ERROR_SHUTDOWN_TIMEOUT,
                  "Timed out waiting for subprocess to exit");
      goto done;
    }

    // Try to read one more character so we know if there are any messages
    // waiting to be read.
    status = g_io_channel_read_chars(child_stdout, &leftover, 1,
                                     &leftover_length, error);
  } while (status == G_IO_STATUS_AGAIN);

  switch (status) {
    case G_IO_STATUS_NORMAL:
      g_assert(leftover_length == 1);
      g_set_error(error, ESCALATE_SUBPROCESS_ERROR,
                  ESCALATE_SUBPROCESS_ERROR_LEFTOVER_STDOUT,
                  "Subprocess stdout had unread messages");
      break;
    case G_IO_STATUS_EOF:
      result = TRUE;
      break;
    default:
      g_assert(!error || *error);
  }

done:
  if (!result && self->child_pid > 0) {
    g_assert(kill(self->child_pid, SIGKILL) == 0);
    self->child_pid = 0;
  }
  g_io_channel_unref(child_stdout);
  return result;
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
  g_assert(self->child_stdin);
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
  g_assert(self->child_stdout);
  return EscalateMessageRead(self->child_stdout, error);
}


GQuark _EscalateSubprocessErrorQuark() {
  return g_quark_from_string("escalate-subprocess-error-quark");
}
