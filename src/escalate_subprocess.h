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

#ifndef ESCALATE_SUBPROCESS_H_
#define ESCALATE_SUBPROCESS_H_

#include "escalate_message.h"

#include <glib.h>

#define ESCALATE_SUBPROCESS_ERROR _EscalateSubprocessErrorQuark()

typedef enum {
  ESCALATE_SUBPROCESS_ERROR_SHUTDOWN_TIMEOUT,
  ESCALATE_SUBPROCESS_ERROR_KILLED,
  ESCALATE_SUBPROCESS_ERROR_LEFTOVER_STDOUT,
} EscalateSubprocessError;

typedef struct {
  gint _refcount;
  GPid child_pid;
  GIOChannel *child_stdin;
  GIOChannel *child_stdout;
} EscalateSubprocess;


EscalateSubprocess *EscalateSubprocessNew(const gchar *path, GError **error);
void EscalateSubprocessRef(EscalateSubprocess *self);
void EscalateSubprocessUnref(EscalateSubprocess *self);

gboolean EscalateSubprocessShutdown(EscalateSubprocess *self, guint timeout_ms,
                                    GError **error);

gboolean EscalateSubprocessSend(EscalateSubprocess *self,
                                EscalateMessage *message, GError **error);
EscalateMessage *EscalateSubprocessRecv(EscalateSubprocess *self,
                                        GError **error);

GQuark _EscalateSubprocessErrorQuark();

#endif
