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

#include <glib-unix.h>
#include <string.h>

static const gchar *example_messages [] = {
  "(1, <(1, 0, 'testuser', {2: @ms 'testuser'})>)",
  "(2, <(1, 'Password: ')>)",
  "(3, <('testpass', 0)>)",
  "(4, <(0,)>)",
};

static const EscalateMessageType example_message_types [] = {
  ESCALATE_MESSAGE_TYPE_START,
  ESCALATE_MESSAGE_TYPE_CONV_MESSAGE,
  ESCALATE_MESSAGE_TYPE_CONV_RESPONSE,
  ESCALATE_MESSAGE_TYPE_FINISH,
};


static GVariant *CreateExampleMessageValues(guint example_message_index) {
  GVariantBuilder items;
  switch (example_message_index) {
    case 0:
      g_variant_builder_init(&items, G_VARIANT_TYPE_ARRAY);
      g_variant_builder_add(&items, "{ims}", 2, "testuser");
      return g_variant_new("(iisa{ims})", 1, 0, "testuser", &items);
    case 1:
      return g_variant_new("(is)", 1, "Password: ");
    case 2:
      return g_variant_new("(si)", "testpass", 0);
    case 3:
      return g_variant_new("(i)", 0);
    default:
      g_error("No message available for index %d", example_message_index);
      return NULL;  // Never reached.
  }
}


static void TestNew(gconstpointer user_data) {
  guint index = GPOINTER_TO_UINT(user_data);
  GVariantBuilder items;
  EscalateMessage *message = NULL;
  GVariant *expected_values = CreateExampleMessageValues(index);

  switch (index) {
    case 0:
      g_variant_builder_init(&items, G_VARIANT_TYPE_ARRAY);
      g_variant_builder_add(&items, "{ims}", 2, "testuser");
      message = EscalateMessageNew(ESCALATE_MESSAGE_TYPE_START, 1, 0,
                                   "testuser", &items);
      break;
    case 1:
      message = EscalateMessageNew(ESCALATE_MESSAGE_TYPE_CONV_MESSAGE, 1,
                                   "Password: ");
      break;
    case 2:
      message = EscalateMessageNew(ESCALATE_MESSAGE_TYPE_CONV_RESPONSE,
                                   "testpass", 0);
      break;
    case 3:
      message = EscalateMessageNew(ESCALATE_MESSAGE_TYPE_FINISH, 0);
      break;
    default:
      g_error("No message available for index %d", index);
  }

  g_assert(message);
  g_assert_cmpint(EscalateMessageGetType(message), ==,
                  example_message_types[index]);
  g_assert(g_variant_equal(expected_values, message->values));

  EscalateMessageUnref(message);
  g_variant_unref(expected_values);
}


static void TestGetValues(gconstpointer user_data) {
  guint index = GPOINTER_TO_UINT(user_data);
  EscalateMessage *message = NULL;
  gint action = 0;
  gint flags = 0;
  gchar *username = NULL;
  gint key = 0;
  gchar *value = NULL;
  GVariantIter *iter = NULL;

  message = EscalateMessageLoad(example_messages[index], NULL);
  g_assert(message);

  switch (index) {
    case 0:
      EscalateMessageGetValues(message, &action, &flags, &username, &iter);
      g_assert_cmpint(1, ==, action);
      g_assert_cmpint(0, ==, flags);
      g_assert_cmpstr("testuser", ==, username);
      g_assert(g_variant_iter_next(iter, "{ims}", &key, &value));
      g_assert_cmpint(2, ==, key);
      g_assert_cmpstr("testuser", ==, value);
      g_assert(!g_variant_iter_next(iter, "{ims}", NULL, NULL));
      g_variant_iter_free(iter);
      g_free(value);
      break;
    case 1:
      EscalateMessageGetValues(message, &flags, &value);
      g_assert_cmpint(1, ==, flags);
      g_assert_cmpstr("Password: ", ==, value);
      g_free(value);
      break;
    case 2:
      EscalateMessageGetValues(message, &value, &flags);
      g_assert_cmpstr("testpass", ==, value);
      g_assert_cmpint(0, ==, flags);
      g_free(value);
      break;
    case 3:
      EscalateMessageGetValues(message, &flags);
      g_assert_cmpint(0, ==, flags);
      break;
    default:
      g_error("No message available for index %d", index);
  }
}


static void TestLoad(gconstpointer user_data) {
  guint index = GPOINTER_TO_UINT(user_data);
  GError *error = NULL;
  GVariant *expected_values = CreateExampleMessageValues(index);

  EscalateMessage *message = EscalateMessageLoad(example_messages[index],
                                                 &error);
  g_assert_no_error(error);
  g_assert(message);
  g_assert_cmpint(EscalateMessageGetType(message), ==,
                  example_message_types[index]);
  g_assert(g_variant_equal(expected_values, message->values));

  g_variant_unref(expected_values);
  EscalateMessageUnref(message);
}


static void TestDump(gconstpointer user_data) {
  guint index = GPOINTER_TO_UINT(user_data);
  GError *error = NULL;
  EscalateMessage *message = EscalateMessageLoad(example_messages[index],
                                                 &error);
  g_assert_no_error(error);
  g_assert(message);

  gchar *message_str = EscalateMessageDump(message);
  g_assert_cmpstr(example_messages[index], ==, message_str);

  g_free(message_str);
  EscalateMessageUnref(message);
}


typedef struct {
  GIOChannel *channel;
  const gchar *contents;
} WriterThreadContext;


static gpointer WriterThread(WriterThreadContext *ctx) {
  GError *error = NULL;
  GIOStatus status;

  status = g_io_channel_write_chars(ctx->channel, ctx->contents, -1, NULL,
                                    &error);
  g_assert_no_error(error);
  g_assert_cmpint(G_IO_STATUS_NORMAL, ==, status);

  status = g_io_channel_shutdown(ctx->channel, TRUE, NULL);
  g_assert_cmpint(G_IO_STATUS_NORMAL, ==, status);
  return NULL;
}


static void TestRead(gconstpointer user_data) {
  guint index = GPOINTER_TO_UINT(user_data);
  gint fds [] = { 0, 0 };
  GIOChannel *reader = NULL;
  WriterThreadContext thread_ctx = { NULL, NULL };
  GThread *thread = NULL;
  GError *error = NULL;
  EscalateMessage *message = NULL;
  GVariant *expected_values = CreateExampleMessageValues(index);

  g_assert(g_unix_open_pipe(fds, 0, NULL));
  reader = g_io_channel_unix_new(fds[0]);

  thread_ctx.channel = g_io_channel_unix_new(fds[1]);
  thread_ctx.contents = example_messages[index];
  thread = g_thread_new("Writer", (GThreadFunc) WriterThread, &thread_ctx);
  g_assert(thread);

  message = EscalateMessageRead(reader, &error);
  g_assert_no_error(error);
  g_assert(message);
  g_assert_cmpint(EscalateMessageGetType(message), ==,
                  example_message_types[index]);
  g_assert(g_variant_equal(expected_values, message->values));
  EscalateMessageUnref(message);

  message = EscalateMessageRead(reader, &error);
  g_assert_error(error, ESCALATE_MESSAGE_ERROR, ESCALATE_MESSAGE_ERROR_EOF);
  g_assert(!message);
  g_error_free(error);

  g_thread_join(thread);
  g_thread_unref(thread);
  g_variant_unref(expected_values);
  g_io_channel_shutdown(reader, FALSE, NULL);
  g_io_channel_unref(reader);
  g_io_channel_unref(thread_ctx.channel);
}


static gchar *ReaderThread(GIOChannel *channel) {
  gchar *result = NULL;
  gsize result_len = 0;
  GError *error = NULL;
  GIOStatus status = g_io_channel_read_to_end(channel, &result, &result_len,
                                              &error);
  g_assert_no_error(error);
  g_assert_cmpint(G_IO_STATUS_NORMAL, ==, status);
  g_assert_cmpint(result_len, ==, strlen(result));
  g_io_channel_shutdown(channel, FALSE, NULL);
  return result;
}


static void TestWrite(gconstpointer user_data) {
  guint index = GPOINTER_TO_UINT(user_data);
  gint fds [] = { 0, 0 };
  GIOChannel *reader = NULL;
  GIOChannel *writer = NULL;
  GThread *thread = NULL;
  EscalateMessage *message = NULL;
  GError *error = NULL;
  gboolean success = FALSE;
  gchar *result = NULL;

  g_assert(g_unix_open_pipe(fds, 0, NULL));
  reader = g_io_channel_unix_new(fds[0]);
  writer = g_io_channel_unix_new(fds[1]);

  thread = g_thread_new("Reader", (GThreadFunc) ReaderThread, reader);

  message = EscalateMessageLoad(example_messages[index], NULL);
  g_assert(message);
  success = EscalateMessageWrite(message, writer, &error);
  g_assert_no_error(error);
  g_assert(success);

  g_assert_cmpint(G_IO_STATUS_NORMAL, ==,
                  g_io_channel_shutdown(writer, TRUE, NULL));

  result = (gchar *) g_thread_join(thread);
  result[strlen(result)-1] = '\0';  // Cut off newline.
  g_assert_cmpstr(example_messages[index], ==, result);

  g_io_channel_unref(reader);
  g_io_channel_unref(writer);
  g_thread_unref(thread);
  EscalateMessageUnref(message);
  g_free(result);
}


static void AddTest(const gchar *short_name, guint index,
                    GTestDataFunc test_func) {
  gchar *test_path = g_strdup_printf("/escalate_message_test/%s%d", short_name,
                                     index);
  g_test_add_data_func(test_path, GUINT_TO_POINTER(index), test_func);
  g_free(test_path);
}


int main(int argc, char **argv) {
  g_test_init(&argc, &argv, NULL);
  for (guint i = 0; i < G_N_ELEMENTS(example_messages); i++) {
    AddTest("TestNew", i, TestNew);
    AddTest("TestGetValues", i, TestGetValues);
    AddTest("TestLoad", i, TestLoad);
    AddTest("TestDump", i, TestDump);
    AddTest("TestRead", i, TestRead);
    AddTest("TestWrite", i, TestWrite);
  }
  return g_test_run();
}
