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

#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include "escalate_module.h"
#include "escalate_message.h"

#include <stdlib.h>
#include <syslog.h>

static gint escalate_module_include_items [] = {
  PAM_TTY, PAM_RUSER, PAM_RHOST, PAM_XDISPLAY, PAM_AUTHTOK_TYPE
};


/**
 * EscalateModuleNew:
 * @pamh: PAM handle.
 * @flags: PAM flags.
 * @argc: Number of arguments given to the PAM module.
 * @argv: Array of argument strings given to the PAM module.
 * @helper: Path to helper executable, or #NULL for the default path.
 * @error: (out)(allow-none): Error return location or #NULL.
 *
 * Returns: New #EscalateModule instance.
 */
EscalateModule *EscalateModuleNew(pam_handle_t *pamh, gint flags, gint argc,
                                  const gchar **argv, const gchar *helper,
                                  GError **error) {
  EscalateModule *self = g_new0(EscalateModule, 1);
  gint pam_result = PAM_SYSTEM_ERR;
  const gchar *username = NULL;

  self->pamh = pamh;
  self->flags = flags;
  self->keep_going = TRUE;
  self->result = PAM_SYSTEM_ERR;

  for (guint i = 0; i < argc; i++) {
    const gchar *arg = argv[i];
    if (g_str_equal(arg, "use_first_pass")) {
      self->use_first_pass = TRUE;
    } else if (g_str_equal(arg, "try_first_pass")) {
      self->try_first_pass = TRUE;
    } else {
      g_set_error(error, ESCALATE_MODULE_ERROR,
                  ESCALATE_MODULE_ERROR_UNKNOWN_ARG,
                  "Unknown argument '%s'", arg);
      goto failed;
    }
  }

  pam_result = pam_get_item(pamh, PAM_CONV, (const void **) &self->conv);
  if (pam_result != PAM_SUCCESS) {
    g_error("Failed to get conversation function: %s",
            pam_strerror(pamh, pam_result));
  }

  if (!self->conv) {
    g_set_error(error, ESCALATE_MODULE_ERROR, ESCALATE_MODULE_ERROR_CONV,
                "No conversation function available");
    goto failed;
  }

  pam_result = pam_get_user(pamh, &username, NULL);
  if (pam_result != PAM_SUCCESS) {
    g_set_error(error, ESCALATE_MODULE_ERROR, ESCALATE_MODULE_ERROR_NO_USERNAME,
                "Failed to find a username");
    goto failed;
  }
  self->username = g_strdup(username);

  // TODO(vonhollen): Handle SIGCHLD for this process without messing up an
  // existing handler.
  self->child = EscalateSubprocessNew(helper, error);
  if (!self->child)
    goto failed;

  return self;

failed:
  EscalateModuleFree(self);
  return NULL;
}


/**
 * EscalateModuleFree:
 * @self: Module to free resources from.
 *
 * This PAM module is safe to unload after this function exits. All signal
 * handlers are reset to their original values, all child processes have exited,
 * and no background threads are running.
 *
 * If the module can't be made safe to unload, a new reference must be created
 * with dlopen().
 */
void EscalateModuleFree(EscalateModule *self) {
  // TODO(vonhollen): Make sure the subprocess is dead and reset any changes to
  // signal handlers done in EscalateModuleNew().
  if (self->child)
    EscalateSubprocessUnref(self->child);
  g_free(self->username);
  g_free(self);
}


/**
 * EscalateModuleStartAddItem:
 * @self: Module containing the PAM handle.
 * @items: Array to append PAM item type and value tuples to.
 * @item: Item type of the value to fetch using pam_get_item().
 * @error: (out)(allow-none): Error return location or #NULL.
 *
 * Returns: #TRUE if there was no fatal error.
 */
static gboolean EscalateModuleStartAddItem(EscalateModule *self,
                                           GVariantBuilder *items, gint item,
                                           GError **error) {
  const gchar *value = NULL;
  gint status = pam_get_item(self->pamh, item, (const void **) &value);
  switch (status) {
    case PAM_SUCCESS:
      g_variant_builder_add(items, "{ims}", item, value);
      return TRUE;
    case PAM_BAD_ITEM:
      return TRUE;
    default:
      g_set_error(error, ESCALATE_MODULE_ERROR,
                  ESCALATE_MODULE_ERROR_GET_ITEM_FAILED,
                  "Failed to get PAM item %d: %s", item,
                  pam_strerror(self->pamh, status));
      return FALSE;
  }
}


/**
 * EscalateModuleStart:
 * @self: PAM module being described in the start message.
 * @action: Action being called on this module, like
 * #ESCALATE_MESSAGE_ACTION_AUTHENTICATE when pam_sm_authenticate() is being
 * used.
 * @error: (out)(allow-none): Error return location or #NULL.
 *
 * Returns: #TRUE if the message was sent.
 */
gboolean EscalateModuleStart(EscalateModule *self, EscalateMessageAction action,
                             GError **error) {
  GVariantBuilder *items = NULL;
  EscalateMessage *message = NULL;
  gboolean result = FALSE;

  items = g_variant_builder_new(G_VARIANT_TYPE("a{ims}"));
  for (guint i = 0; i < G_N_ELEMENTS(escalate_module_include_items); i++) {
    gint item = escalate_module_include_items[i];
    if (!EscalateModuleStartAddItem(self, items, item, error)) {
      goto done;
    }
  }

  // TODO(vonhollen): Include environment variables?
  message = EscalateMessageNew(ESCALATE_MESSAGE_TYPE_START, action, self->flags,
                               self->username, items);
  if (EscalateSubprocessSend(self->child, message, error))
    result = TRUE;

done:
  if (message)
    EscalateMessageUnref(message);
  g_variant_builder_unref(items);
  return result;
}


/**
 * EscalateModuleHandleConversation:
 * @self: PAM module to forward conversation messages to.
 * @message: Conversation message from the helper process holding the same
 * values as one "struct pam_message".
 * @error: (out)(allow-none): Error return location or #NULL.
 *
 * Returns: #TRUE if a response message was sent back to the helper process.
 */
static gboolean EscalateModuleHandleConversation(EscalateModule *self,
                                                 EscalateMessage *message,
                                                 GError **error) {
  gchar *conv_message_str = NULL;
  struct pam_message conv_message = { 0, NULL };
  const struct pam_message *conv_message_array [] = { &conv_message, NULL };
  struct pam_response *conv_response = NULL;
  gint pam_status = PAM_SYSTEM_ERR;
  EscalateMessage *response = NULL;
  gboolean result = FALSE;

  EscalateMessageGetValues(message, &conv_message.msg_style, &conv_message_str);
  conv_message.msg = conv_message_str;

  // TODO(vonhollen): Support multiple requests/responses per call.
  pam_status = self->conv->conv(1, conv_message_array, &conv_response,
                                self->conv->appdata_ptr);
  if (pam_status != PAM_SUCCESS) {
    g_set_error(error, ESCALATE_MODULE_ERROR, ESCALATE_MODULE_ERROR_CONV,
                "Conversation function failed: %s",
                pam_strerror(self->pamh, pam_status));
    goto done;
  }

  response = EscalateMessageNew(ESCALATE_MESSAGE_TYPE_CONV_RESPONSE,
                                conv_response[0].resp,
                                conv_response[0].resp_retcode);
  if (EscalateSubprocessSend(self->child, response, error))
    result = TRUE;

done:
  g_free(conv_message_str);
  if (conv_response) {
    free(conv_response[0].resp);
    free(conv_response);
  }
  if (response) {
    EscalateMessageUnref(response);
  }
  return result;
}


/**
 * EscalateModuleHandleFinish:
 * @self: PAM module that should return the result in @message.
 * @message: Message from the helper process containing its final result.
 * @error: (out)(allow-none): Error return location or #NULL. Unused for now,
 * but included to match the signature of EscalateModuleHandleConversation().
 *
 * Returns: #TRUE always.
 */
static gboolean EscalateModuleHandleFinish(EscalateModule *self,
                                           EscalateMessage *message,
                                           GError **error) {
  EscalateMessageGetValues(message, &self->result);
  self->keep_going = FALSE;
  return TRUE;
}


/**
 * EscalateModuleHandleNext:
 * @self: PAM module that's receiving messages from the helper process.
 * @error: (out)(allow-none): Error return location or #NULL.
 *
 * Returns: #TRUE if a message was read and handled without an error.
 */
gboolean EscalateModuleHandleNext(EscalateModule *self, GError **error) {
  EscalateMessage *message = NULL;
  gboolean result = FALSE;

  message = EscalateSubprocessRecv(self->child, error);
  if (!message)
    goto done;

  switch (EscalateMessageGetType(message)) {
    case ESCALATE_MESSAGE_TYPE_CONV_MESSAGE:
      result = EscalateModuleHandleConversation(self, message, error);
      break;
    case ESCALATE_MESSAGE_TYPE_FINISH:
      result = EscalateModuleHandleFinish(self, message, error);
      break;
    default:
      g_set_error(error, ESCALATE_MODULE_ERROR,
                  ESCALATE_MODULE_ERROR_MESSAGE_TYPE,
                  "Unexpected message type: %d",
                  EscalateMessageGetType(message));
      break;
  }

done:
  if (message)
    EscalateMessageUnref(message);
  return result;
}


/**
 * EscalateModuleKeepGoing:
 * @self: PAM module that's receiving messages from the helper process.
 *
 * Returns: #TRUE if the helper hasn't sent the finish message yet.
 */
gboolean EscalateModuleKeepGoing(EscalateModule *self) {
  return self->keep_going;
}


/**
 * EscalateModuleGetResult:
 * @self: PAM module that received a finish message.
 *
 * Returns: PAM status from the finish message, or PAM_SYSTEM_ERR if the finish
 * message hasn't been received.
 */
int EscalateModuleGetResult(EscalateModule *self) {
  return self->result;
}


/**
 * EscalateModuleMain:
 * @action: Action being called on this module, like
 * ESCALATE_MESSAGE_ACTION_AUTHENTICATE for pam_sm_authenticate().
 * @pamh: PAM handle.
 * @flags: PAM flags.
 * @argc: Number of arguments given to the PAM module.
 * @argv: Array of argument strings given to the PAM module.
 *
 * Returns: PAM status to return from the pam_sm_*() functions.
 */
int EscalateModuleMain(EscalateMessageAction action, pam_handle_t *pamh,
                       gint flags, gint argc, const gchar **argv) {
  GError *error = NULL;
  EscalateModule *module = NULL;
  gint result = PAM_SYSTEM_ERR;

  module = EscalateModuleNew(pamh, flags, argc, argv, NULL, &error);
  if (!module)
    goto done;

  if (!EscalateModuleStart(module, action, &error))
    goto done;

  while (EscalateModuleKeepGoing(module)) {
    if (!EscalateModuleHandleNext(module, &error)) {
      goto done;
    }
  }

  result = EscalateModuleGetResult(module);

done:
  if (error) {
    g_assert(result != PAM_SUCCESS);
    pam_syslog(pamh, LOG_WARNING, "%s", error->message);
    g_error_free(error);
  }
  if (module) {
    EscalateModuleFree(module);
  }
  return result;
}


PAM_EXTERN int
pam_sm_authenticate(
    pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return EscalateModuleMain(ESCALATE_MESSAGE_ACTION_AUTHENTICATE, pamh, flags,
                            argc, argv);
}


PAM_EXTERN int
pam_sm_setcred(
    pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return PAM_IGNORE;
}


PAM_EXTERN int
pam_sm_acct_mgmt(
    pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return PAM_IGNORE;
}


PAM_EXTERN int
pam_sm_open_session(
    pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return PAM_IGNORE;
}


PAM_EXTERN int
pam_sm_close_session(
    pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return PAM_IGNORE;
}


PAM_EXTERN int
pam_sm_chauthtok(
    pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return PAM_IGNORE;
}


GQuark _EscalateModuleErrorQuark() {
  return g_quark_from_string("escalate-module-error-quark");
}
