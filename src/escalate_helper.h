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

#ifndef ESCALATE_HELPER_H_
#define ESCALATE_HELPER_H_

#define ESCALATE_HELPER_ERROR _EscalateHelperErrorQuark()

#include "escalate_message.h"

#include <glib.h>
#include <security/pam_appl.h>

#define ESCALATE_SERVICE_NAME "escalate"

typedef enum {
  ESCALATE_HELPER_ERROR_UNEXPECTED_MESSAGE_TYPE,
  ESCALATE_HELPER_ERROR_START_FAILED,
  ESCALATE_HELPER_ERROR_UNKNOWN_USERNAME,
  ESCALATE_HELPER_ERROR_PRIVILEGE_ERROR,
  ESCALATE_HELPER_ERROR_UNSUPPORTED_ITEM,
  ESCALATE_HELPER_ERROR_SET_ITEM_FAILED,
  ESCALATE_HELPER_ERROR_SET_ENV_FAILED,
  ESCALATE_HELPER_ERROR_EXTRA_ARGS,
} EscalateHelperError;

typedef struct {
  GIOChannel *reader;
  GIOChannel *writer;
  gchar *username;
  pam_handle_t *pamh;
  int flags;
  EscalateMessageAction action;
  struct pam_conv conv;
  int result;
} EscalateHelper;

EscalateHelper *EscalateHelperNew(int stdin_fd, int stdout_fd);
void EscalateHelperFree(EscalateHelper *self);

gboolean EscalateHelperHandleStart(EscalateHelper *self, GError **error);
gboolean EscalateHelperDoAction(EscalateHelper *self, GError **error);
int EscalateHelperConversation(int conv_len,
                               const struct pam_message **conv_request,
                               struct pam_response **conv_response,
                               void *user_data);

GQuark _EscalateHelperErrorQuark();

#endif
