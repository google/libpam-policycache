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

#ifndef ESCALATE_MESSAGE_H_
#define ESCALATE_MESSAGE_H_

#include <glib.h>

#define ESCALATE_MESSAGE_ERROR _EscalateMessageErrorQuark()

typedef enum {
  ESCALATE_MESSAGE_ERROR_TYPE,
  ESCALATE_MESSAGE_ERROR_FORMAT,
  ESCALATE_MESSAGE_ERROR_EOF,
} EscalateMessageError;

typedef enum {
  ESCALATE_MESSAGE_TYPE_START = 1,
  ESCALATE_MESSAGE_TYPE_CONV_MESSAGE,
  ESCALATE_MESSAGE_TYPE_CONV_RESPONSE,
  ESCALATE_MESSAGE_TYPE_FINISH,
} EscalateMessageType;

typedef enum {
  ESCALATE_MESSAGE_ACTION_UNKNOWN = 0,
  ESCALATE_MESSAGE_ACTION_AUTHENTICATE = 1,
} EscalateMessageAction;

typedef struct {
  int _refcount;
  EscalateMessageType type;
  GVariant *values;
} EscalateMessage;

EscalateMessage *EscalateMessageNew(EscalateMessageType type, ...);
EscalateMessage *EscalateMessageLoad(const gchar *value, GError **error);
EscalateMessage *EscalateMessageRead(GIOChannel *stream, GError **error);

void EscalateMessageRef(EscalateMessage *self);
void EscalateMessageUnref(EscalateMessage *self);

EscalateMessageType EscalateMessageGetType(EscalateMessage *self);
void EscalateMessageGetValues(EscalateMessage *self, ...);

gchar *EscalateMessageDump(EscalateMessage *self);
gboolean EscalateMessageWrite(EscalateMessage *self, GIOChannel *stream,
                              GError **error);

GQuark _EscalateMessageErrorQuark();

#endif
