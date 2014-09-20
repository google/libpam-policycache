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

#ifndef ESCALATE_UTIL_H_
#define ESCALATE_UTIL_H_

#define ESCALATE_UTIL_ERROR _EscalateUtilErrorQuark()

#include <glib.h>

#ifdef PAM_SM_AUTH
#include <security/pam_modules.h>
#else
#include <security/pam_appl.h>
#endif

typedef enum {
  ESCALATE_UTIL_ERROR_ENVIRONMENT,
} EscalateUtilError;

GVariantBuilder *EscalateUtilPamEnvToVariant(pam_handle_t *pamh,
                                             GError **error);
gboolean EscalateUtilPamEnvFromVariant(pam_handle_t *pam_h, GVariantIter *iter,
                                       GError **error);

GQuark _EscalateUtilErrorQuark();

#endif
