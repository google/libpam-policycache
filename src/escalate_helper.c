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
#include "escalate_message.h"

#include <pwd.h>
#include <security/pam_ext.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>


/**
 * EscalateHelperNew:
 * @stdin_fd: Pipe to read messages from, usually STDIN_FILENO.
 * @stdout_fd: Pipe to write messages to, usually STDOUT_FILENO.
 *
 * Returns: New #EscalateHelper instance.
 */
EscalateHelper *EscalateHelperNew(int stdin_fd, int stdout_fd,
                                  uid_t caller_uid, gid_t caller_gid) {
  EscalateHelper *self = g_new0(EscalateHelper, 1);
  self->reader = g_io_channel_unix_new(stdin_fd);
  self->writer = g_io_channel_unix_new(stdout_fd);
  self->caller_uid = caller_uid;
  self->caller_gid = caller_gid;
  self->conv.conv = EscalateHelperConversation;
  self->conv.appdata_ptr = self;
  self->result = PAM_SYSTEM_ERR;
  g_assert(self->caller_uid >= 0);
  g_assert(self->caller_gid >= 0);
  return self;
}


void EscalateHelperFree(EscalateHelper *self) {
  if (self->pamh) {
    int pam_status = pam_end(self->pamh, self->result);
    if (pam_status != PAM_SUCCESS) {
      g_error("pam_end returned unexpected code %d: %s", pam_status,
              pam_strerror(self->pamh, pam_status));
    }
  }
  g_io_channel_unref(self->reader);
  g_io_channel_unref(self->writer);
  g_free(self->username);
  g_free(self);
}


/**
 * EscalateHelperIsSafeItem:
 * @item_type: PAM item type, see pam_get_item.
 *
 * Returns: #TRUE if it's OK to call pam_set_item with an untrusted string
 * value for the given item type.
 */
static gboolean EscalateHelperIsSafeItem(int item_type) {
  switch (item_type) {
    case PAM_TTY:
    case PAM_RUSER:
    case PAM_RHOST:
    case PAM_XDISPLAY:
    case PAM_AUTHTOK_TYPE:
      return TRUE;
    default:
      return FALSE;
  }
}


/**
 * EscalateHelperRecv:
 * @self: #EscalateHelper instance.
 * @type: Only accept a message with this type.
 * @error: (out)(allow-none): Error return location or #NULL.
 *
 * Returns: New #EscalateMessage instance, or #NULL on error.
 */
static EscalateMessage *EscalateHelperRecv(EscalateHelper *self,
                                           EscalateMessageType type,
                                           GError **error) {
  EscalateMessage *message = EscalateMessageRead(self->reader, error);
  if (!message)
    return NULL;

  if (EscalateMessageGetType(message) == type)
    return message;

  g_set_error(error, ESCALATE_HELPER_ERROR,
              ESCALATE_HELPER_ERROR_UNEXPECTED_MESSAGE_TYPE,
              "Expected message type %d but got %d instead", type,
              EscalateMessageGetType(message));
  EscalateMessageUnref(message);
  return NULL;
}


/**
 * EscalateHelperIsUserAllowed:
 * @self: #EscalateHelper instance.
 * @error: (out)(allow-none): Error return location or #NULL.
 *
 * Root can run the helper for any user, and non-root users are only allowed to
 * run the helper for themselves.
 *
 * Returns: #TRUE if it's safe to try authentication for the user specified in
 * the start message.
 */
static gboolean EscalateHelperIsUserAllowed(EscalateHelper *self,
                                            GError **error) {
  struct passwd *user = NULL;
  g_assert(self->username);

  if (self->caller_uid == 0 && self->caller_gid == 0)
    return TRUE;

  user = getpwnam(self->username);
  if (!user) {
    g_set_error(error, ESCALATE_HELPER_ERROR,
                ESCALATE_HELPER_ERROR_UNKNOWN_USERNAME,
                "Failed to find uid for user '%s'", self->username);
    return FALSE;
  }

  if (user->pw_uid != self->caller_uid) {
    g_set_error(error, ESCALATE_HELPER_ERROR,
                ESCALATE_HELPER_ERROR_PRIVILEGE_ERROR,
                "Can't use escalate for user '%s' (uid=%d) when running as"
                " another user (uid=%d)", self->username, user->pw_uid,
                self->caller_uid);
    return FALSE;
  }

  return TRUE;
}


/**
 * EscalateHelperHandleStart:
 * @self: #EscalateHelper instance.
 * @error: (out)(allow-none): Error return location or #NULL.
 *
 * Return: #TRUE if pam_start() was called and it's OK to call
 * EscalateHelperDoAction(). #FALSE if there was an error and the finish message
 * was sent.
 */
gboolean EscalateHelperHandleStart(EscalateHelper *self, GError **error) {
  EscalateMessage *message = NULL;
  EscalateMessage *response = NULL;
  GVariantIter *items = NULL;
  GVariantIter *env = NULL;
  int pam_status = PAM_SYSTEM_ERR;
  int item_type = -1;
  const gchar *item_value = NULL;
  const gchar *env_key = NULL;
  const gchar *env_value = NULL;
  gboolean result = FALSE;

  // Support EscalateHelperHandleStart() being called multiple times.
  self->action = ESCALATE_MESSAGE_ACTION_UNKNOWN;
  self->flags = 0;
  g_free(self->username);
  self->username = NULL;
  self->result = PAM_SYSTEM_ERR;

  message = EscalateHelperRecv(self, ESCALATE_MESSAGE_TYPE_START, error);
  if (!message)
    goto done;

  EscalateMessageGetValues(message, &self->action, &self->flags,
                           &self->username, &items, &env);

  if (!EscalateHelperIsUserAllowed(self, error))
    goto done;

  // TODO(vonhollen): Safely allow calls to multiple services.
  pam_status = pam_start(ESCALATE_SERVICE_NAME, self->username, &self->conv,
                         &self->pamh);
  if (pam_status != PAM_SUCCESS) {
    g_set_error(error, ESCALATE_HELPER_ERROR,
                ESCALATE_HELPER_ERROR_START_FAILED,
                "Failed to start PAM session: %s",
                pam_strerror(self->pamh, pam_status));
    goto done;
  }

  while (g_variant_iter_loop(items, "{im&s}", &item_type, &item_value)) {
    if (!EscalateHelperIsSafeItem(item_type)) {
      g_set_error(error, ESCALATE_HELPER_ERROR,
                  ESCALATE_HELPER_ERROR_UNSUPPORTED_ITEM,
                  "Item type %d is not supported", item_type);
      goto done;
    }
    pam_status = pam_set_item(self->pamh, item_type, item_value);
    if (pam_status != PAM_SUCCESS) {
      g_set_error(error, ESCALATE_HELPER_ERROR,
                  ESCALATE_HELPER_ERROR_SET_ITEM_FAILED,
                  "Failed to set item type %d to '%s'", item_type, item_value);
      goto done;
    }
  }

  while (g_variant_iter_loop(env, "{&s&s}", &env_key, &env_value)) {
    g_assert(env_key);
    g_assert(env_value);
    gchar *env_pair = g_strdup_printf("%s=%s", env_key, env_value);
    pam_status = pam_putenv(self->pamh, env_pair);
    g_free(env_pair);
    if (pam_status != PAM_SUCCESS) {
      g_set_error(error, ESCALATE_HELPER_ERROR,
                  ESCALATE_HELPER_ERROR_SET_ENV_FAILED,
                  "Failed to set environment variable '%s' to '%s'",
                  env_key, env_value);
      goto done;
    }
  }

  result = TRUE;

done:
  if (!result) {
    response = EscalateMessageNew(ESCALATE_MESSAGE_TYPE_FINISH, PAM_SYSTEM_ERR,
                                  NULL);
    EscalateMessageWrite(response, self->writer, NULL);
    EscalateMessageUnref(response);
  }

  if (items)
    g_variant_iter_free(items);
  if (env)
    g_variant_iter_free(env);
  if (message)
    EscalateMessageUnref(message);
  return result;
}


/**
 * EscalateHelperDoAction:
 * @self: #EscalateHelper instance.
 * @error: (out)(allow-none): Error return location or #NULL.
 *
 * Return: #TRUE if the action specified in the start message (just
 * pam_authenticate for now) was called successfully and the finish message was
 * sent.
 */
gboolean EscalateHelperDoAction(EscalateHelper *self, GError **error) {
  int setcred_result = PAM_SUCCESS;
  EscalateMessage *message = NULL;
  gchar **env_lines = NULL;
  GVariantBuilder env;
  gboolean success = FALSE;

  // Run the action specified in the start message.
  switch (self->action) {
    case ESCALATE_MESSAGE_ACTION_AUTHENTICATE:
      self->result = pam_authenticate(self->pamh, self->flags);
      if (self->result == PAM_SUCCESS || self->result == PAM_NEW_AUTHTOK_REQD) {
        // Refresh things like Kerberos credentials. This is safe to do here
        // even if the client never calls pam_setcred() because the entire auth
        // stack succeeded.
        // TODO(vonhollen): Make this configurable by pam_escalate.so.
        setcred_result = pam_setcred(self->pamh, PAM_REFRESH_CRED);
        if (setcred_result != PAM_SUCCESS) {
          pam_syslog(self->pamh, LOG_NOTICE,
                     "pam_setcred() failed for user '%s': %s",
                     self->username, pam_strerror(self->pamh, setcred_result));
        }
      }
      break;
    default:
      self->result = PAM_SYSTEM_ERR;
      g_error("Unsupported action %d", self->action);
  }

  // Prevent this function from being run twice.
  self->action = ESCALATE_MESSAGE_ACTION_UNKNOWN;

  // Get the PAM environment to include in the result.
  g_variant_builder_init(&env, G_VARIANT_TYPE_ARRAY);
  env_lines = pam_getenvlist(self->pamh);
  if (env_lines) {
    for (guint i = 0; env_lines[i]; i++) {
      gchar **env_pair = g_strsplit(env_lines[i], "=", 2);
      if (env_pair[0] && env_pair[1]) {
        g_variant_builder_add(&env, "{ss}", env_pair[0], env_pair[1]);
      }
      g_strfreev(env_pair);
      free(env_lines[i]);
    }
    free(env_lines);
  }

  // Send the final PAM result for the action and the complete environment.
  message = EscalateMessageNew(ESCALATE_MESSAGE_TYPE_FINISH, self->result,
                               &env);
  success = EscalateMessageWrite(message, self->writer, error);
  EscalateMessageUnref(message);
  return success;
}


/**
 * EscalateHelperPrompt:
 * @self: #EscalateHelper instance.
 * @conv_request: Conversation message to send.
 * @conv_response: Conversation response contents received.
 *
 * Returns: PAM_SUCCESS if one message was sent and response was read, or
 * PAM_CONV_ERROR on failure. Error are logged with pam_syslog.
 */
static int EscalateHelperPrompt(EscalateHelper *self,
                                const struct pam_message *conv_request,
                                struct pam_response *conv_response) {
  EscalateMessage *request = NULL;
  GError *error = NULL;
  EscalateMessage *response = NULL;
  gchar *response_msg = NULL;
  int response_retcode = 0;
  int result = PAM_CONV_ERR;

  request = EscalateMessageNew(ESCALATE_MESSAGE_TYPE_CONV_MESSAGE,
                               conv_request->msg_style, conv_request->msg);

  if (!EscalateMessageWrite(request, self->writer, &error)) {
    pam_syslog(self->pamh, LOG_WARNING,
               "Failed to write conversation request: %s", error->message);
    g_clear_error(&error);
    goto done;
  }

  response = EscalateHelperRecv(self, ESCALATE_MESSAGE_TYPE_CONV_RESPONSE,
                                &error);
  if (!response) {
    pam_syslog(self->pamh, LOG_WARNING,
               "Failed to read conversation response: %s", error->message);
    g_clear_error(&error);
    goto done;
  }

  EscalateMessageGetValues(response, &response_msg, &response_retcode);

  if (response_msg) {
    conv_response->resp = strdup(response_msg);
  } else {
    conv_response->resp = NULL;
  }

  conv_response->resp_retcode = response_retcode;
  result = PAM_SUCCESS;

done:
  if (request)
    EscalateMessageUnref(request);
  if (response)
    EscalateMessageUnref(response);
  g_free(response_msg);
  return result;
}


/**
 * EscalateHelperConversation:
 * @conv_len: Number of messages in the conversation.
 * @conv_requests: Array of pointers to messages to send.
 * @conv_responses: (out)(transfer-full): Pointer which is set to an array
 * of response structs. The caller must free() the array and the string value
 * in each response.
 *
 * Return: PAM_SUCCESS if each request was sent and each response was read using
 * EscalateHelperPrompt(), or PAM_CONV_ERR if there was any problem.
 */
int EscalateHelperConversation(int conv_len,
                               const struct pam_message **conv_requests,
                               struct pam_response **conv_responses,
                               void *user_data) {
  EscalateHelper *self = (EscalateHelper *) user_data;
  struct pam_response *tmp_conv_responses = NULL;
  int result = PAM_SUCCESS;

  if (conv_len == 0) {
    pam_syslog(self->pamh, LOG_WARNING,
               "Conversation function called with no messages");
    return PAM_CONV_ERR;
  }

  tmp_conv_responses = calloc(conv_len, sizeof(struct pam_response));
  g_assert(tmp_conv_responses);

  for (guint i = 0; i < conv_len; i++) {
    g_assert(conv_requests[i]);
    result = EscalateHelperPrompt(self, conv_requests[i],
                                  &tmp_conv_responses[i]);
    if (result != PAM_SUCCESS)
      break;
  }

  if (result == PAM_SUCCESS) {
    *conv_responses = tmp_conv_responses;
  } else {
    for (guint i = 0; i < conv_len; i++) {
      if (tmp_conv_responses[i].resp) {
        free(tmp_conv_responses[i].resp);
      }
    }
    free(tmp_conv_responses);
  }

  return result;
}


#ifndef ESCALATE_HELPER_TESTING
int main(int argc, char **argv) {
  GError *error = NULL;
  GOptionContext *context = NULL;
  uid_t orig_uid = -1;
  gid_t orig_gid = -1;
  EscalateHelper *helper = NULL;
  int exit_code = 2;

  clearenv();
  umask(0077);

  context = g_option_context_new("- helper for pam_escalate.so");
  if (!g_option_context_parse(context, &argc, &argv, &error)) {
    goto done;
  }

  if (argc > 1) {
    g_set_error(&error, ESCALATE_HELPER_ERROR, ESCALATE_HELPER_ERROR_EXTRA_ARGS,
                "Non-flag arguments are not accepted");
    goto done;
  }

  orig_uid = getuid();
  orig_gid = getgid();

  if (orig_uid != geteuid()) {
    setuid(geteuid());
  }

  if (orig_gid != getegid()) {
    setgid(getegid());
  }

  helper = EscalateHelperNew(STDIN_FILENO, STDOUT_FILENO, orig_uid, orig_gid);

  if (!EscalateHelperHandleStart(helper, &error)) {
    goto done;
  }

  if (EscalateHelperDoAction(helper, &error)) {
    exit_code = 0;
  } else {
    exit_code = 1;
  }

done:
  if (error) {
    g_printerr("Caught error: %s\n", error->message);
    g_error_free(error);
  }
  EscalateHelperFree(helper);
  return exit_code;
}
#endif


GQuark _EscalateHelperErrorQuark() {
  return g_quark_from_string("escalate-helper-error-quark");
}
