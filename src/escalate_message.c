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


typedef struct {
  EscalateMessageType type;
  const gchar *fmt;
} EscalateMessageFormat;

static EscalateMessageFormat escalate_message_formats [] = {
  { ESCALATE_MESSAGE_TYPE_START, "(iisa{ims})" },
  { ESCALATE_MESSAGE_TYPE_CONV_MESSAGE, "(is)" },
  { ESCALATE_MESSAGE_TYPE_CONV_RESPONSE, "(si)" },
  { ESCALATE_MESSAGE_TYPE_FINISH, "(i)" },
};


static const gchar *EscalateMessageGetFormat(EscalateMessageType type) {
  for (guint i = 0; i < G_N_ELEMENTS(escalate_message_formats); i++) {
    if (escalate_message_formats[i].type == type) {
      return escalate_message_formats[i].fmt;
    }
  }
  return NULL;
}


EscalateMessage *EscalateMessageNew(EscalateMessageType type, ...) {
  const gchar *fmt = EscalateMessageGetFormat(type);
  EscalateMessage *self = g_new0(EscalateMessage, 1);
  va_list args;
  g_assert(fmt);
  va_start(args, type);
  self->_refcount = 1;
  self->type = type;
  self->values = g_variant_new_va(fmt, NULL, &args);
  va_end(args);
  return self;
}


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
  g_variant_ref(values);

done:
  if (message)
    g_variant_unref(message);
  if (values)
    g_variant_unref(values);
  return self;
}


EscalateMessage *EscalateMessageRead(GIOChannel *stream, GError **error) {
  gchar *line = NULL;
  gsize line_term = 0;
  EscalateMessage *self = NULL;

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
      goto done;
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


void EscalateMessageGetValues(EscalateMessage *self, ...) {
  const gchar *fmt = EscalateMessageGetFormat(self->type);
  va_list args;
  va_start(args, self);
  g_assert(fmt);
  g_variant_get_va(self->values, fmt, NULL, &args);
  va_end(args);
}


gchar *EscalateMessageDump(EscalateMessage *self) {
  g_variant_ref(self->values);
  GVariant *message = g_variant_new("(iv)", self->type, self->values);
  gchar *result = g_variant_print(message, TRUE);
  g_variant_unref(message);
  return result;
}


gboolean EscalateMessageWrite(EscalateMessage *self, GIOChannel *stream,
                              GError **error) {
  gchar *message_str = EscalateMessageDump(self);
  gsize message_len = strlen(message_str);
  gsize written = 0;
  GIOStatus io_status = 0;
  gboolean result = FALSE;

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