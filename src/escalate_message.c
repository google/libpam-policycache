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

#include <string.h>

static struct {
  EscalateMessageType type;
  const gchar *fmt;
} escalate_message_formats [] = {
  { ESCALATE_MESSAGE_TYPE_START, "(iisa{ims})" },
  { ESCALATE_MESSAGE_TYPE_CONV_MESSAGE, "(is)" },
  { ESCALATE_MESSAGE_TYPE_CONV_RESPONSE, "(msi)" },
  { ESCALATE_MESSAGE_TYPE_FINISH, "(i)" },
};


/**
 * EscalateMessageGetFormat:
 * @type: Message type.
 *
 * Returns: GVariant format string describing the values of any message with
 * that type. Suitable for format_string in g_variant_new(), g_variant_get(),
 * etc.
 */
static const gchar *EscalateMessageGetFormat(EscalateMessageType type) {
  for (guint i = 0; i < G_N_ELEMENTS(escalate_message_formats); i++) {
    if (escalate_message_formats[i].type == type) {
      return escalate_message_formats[i].fmt;
    }
  }
  return NULL;
}


/**
 * EscalateMessageNew:
 * @type: The #EscalateMessageType value for the new message.
 * @...: Arguments for the values contained in the message, passed to
 * g_variant_new_va().
 *
 * The format string used for g_variant_new_va is selected using the @type
 * value.
 *
 * Returns: New #EscalateMessage instance.
 */
EscalateMessage *EscalateMessageNew(EscalateMessageType type, ...) {
  const gchar *fmt = EscalateMessageGetFormat(type);
  EscalateMessage *self = g_new0(EscalateMessage, 1);
  va_list args;
  g_assert(fmt);
  va_start(args, type);
  self->_refcount = 1;
  self->type = type;
  self->values = g_variant_ref_sink(g_variant_new_va(fmt, NULL, &args));
  va_end(args);
  return self;
}


/**
 * EscalateMessageLoad:
 * @value: Message string to parse.
 * @error: (out)(allow-none): Error return location or #NULL.
 *
 * Returns: New #EscalateMessage instance, or #NULL on error.
 */
EscalateMessage *EscalateMessageLoad(const gchar *value, GError **error) {
  GVariant *message = NULL;
  EscalateMessageType type = 0;
  GVariant *values = NULL;
  const gchar *values_fmt = NULL;
  EscalateMessage *self = NULL;

  message = g_variant_parse(G_VARIANT_TYPE("(iv)"), value, NULL, NULL, error);
  if (!message)
    return NULL;

  g_variant_get(message, "(iv)", &type, &values);

  values_fmt = EscalateMessageGetFormat(type);
  if (!values_fmt) {
    g_set_error(error, ESCALATE_MESSAGE_ERROR, ESCALATE_MESSAGE_ERROR_TYPE,
                "Unknown message type: %d", type);
    goto done;
  }

  if (!g_variant_is_of_type(values, G_VARIANT_TYPE(values_fmt))) {
    g_set_error(error, ESCALATE_MESSAGE_ERROR, ESCALATE_MESSAGE_ERROR_FORMAT,
                "Expected message format %s but got %s", values_fmt,
                g_variant_get_type_string(values));
    goto done;
  }

  self = g_new0(EscalateMessage, 1);
  self->_refcount = 1;
  self->type = type;
  self->values = values;
  values = NULL;

done:
  if (message)
    g_variant_unref(message);
  if (values)
    g_variant_unref(values);
  return self;
}


/**
 * EscalateMessageRead:
 * @stream: Stream to read one message line from. Must be in blocking mode.
 * @error: (out)(allow-none): Error return location or #NULL.
 *
 * Returns: New #EscalateMessage instance, or #NULL on error.
 */
EscalateMessage *EscalateMessageRead(GIOChannel *stream, GError **error) {
  gchar *line = NULL;
  gsize line_term = 0;
  EscalateMessage *self = NULL;

  g_assert(!(g_io_channel_get_flags(stream) & G_IO_FLAG_NONBLOCK));

  switch (g_io_channel_read_line(stream, &line, NULL, &line_term,
                                 error)) {
    case G_IO_STATUS_NORMAL:
      break;
    case G_IO_STATUS_EOF:
      g_set_error(error, ESCALATE_MESSAGE_ERROR,
                  ESCALATE_MESSAGE_ERROR_EOF,
                  "Failed to read next message from stream");
      goto done;
    case G_IO_STATUS_ERROR:
      goto done;  // *error is already set by g_io_channel_read_line().
    default:
      g_error("Unexpected status from g_io_channel_read_line");
  }

  line[line_term] = 0;
  self = EscalateMessageLoad(line, error);

done:
  g_free(line);
  return self;
}


void EscalateMessageRef(EscalateMessage *self) {
  g_assert(self->_refcount > 0);
  self->_refcount++;
}


void EscalateMessageUnref(EscalateMessage *self) {
  g_assert(self->_refcount > 0);
  self->_refcount--;
  if (self->_refcount)
    return;

  g_variant_unref(self->values);
  g_free(self);
}


EscalateMessageType EscalateMessageGetType(EscalateMessage *self) {
  return self->type;
}


/**
 * EscalateMessageGetValues:
 * @self: #EscalateMessage instance to get values from.
 * @...: Pointers to where to store copies of the values, just like the
 * arguments to g_variant_get.
 *
 * The format given to g_variant_get_va() is provided by the message type.
 */
void EscalateMessageGetValues(EscalateMessage *self, ...) {
  const gchar *fmt = EscalateMessageGetFormat(self->type);
  va_list args;
  va_start(args, self);
  g_assert(fmt);
  g_variant_get_va(self->values, fmt, NULL, &args);
  va_end(args);
}


/**
 * EscalateMessageDump:
 * @self: #EscalateMessage instance to serialize.
 *
 * Returns: Human-readable string representing the message that never contains
 * unescaped newlines. See g_variant_print for more about the text format.
 */
gchar *EscalateMessageDump(EscalateMessage *self) {
  GVariant *message = g_variant_new("(iv)", self->type, self->values);
  gchar *result = g_variant_print(message, TRUE);
  g_variant_unref(message);
  g_assert(!g_strrstr(result, "\n"));
  return result;
}


/**
 * EscalateMessageWrite:
 * @self: #EscalateMessage instance to serialize and write.
 * @stream: Stream to write the message string and a newline to. Must be in
 * blocking mode.
 * @error: (out)(allow-none): Error return location or #NULL.
 *
 * Returns: #TRUE if the message text and newline were written to the stream.
 */
gboolean EscalateMessageWrite(EscalateMessage *self, GIOChannel *stream,
                              GError **error) {
  gchar *message_str = EscalateMessageDump(self);
  gsize message_len = strlen(message_str);
  gsize written = 0;
  GIOStatus io_status = 0;
  gboolean result = FALSE;

  g_assert(!(g_io_channel_get_flags(stream) & G_IO_FLAG_NONBLOCK));

  message_str[message_len] = '\n';
  message_len++;

  io_status = g_io_channel_write_chars(stream, message_str, message_len,
                                       &written, error);
  switch (io_status) {
    case G_IO_STATUS_NORMAL:
      g_assert(written == message_len);
      break;
    case G_IO_STATUS_ERROR:
      goto done;
    default:
      g_error("Unexpected status while writing message: %d", io_status);
  }

  io_status = g_io_channel_flush(stream, error);
  switch (io_status) {
    case G_IO_STATUS_NORMAL:
      result = TRUE;
      break;
    case G_IO_STATUS_ERROR:
      goto done;
    default:
      g_error("Unexpected status while flushing message: %d", io_status);
  }

done:
  g_free(message_str);
  return result;
}


GQuark _EscalateMessageErrorQuark() {
  return g_quark_from_string("escalate-message-error-quark");
}
