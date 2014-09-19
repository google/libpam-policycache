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

#include "escalate_util.h"

#include <stdlib.h>
#include <string.h>


/**
 * EscalateUtilPamEnvToVariant:
 * @pamh: PAM handle with environment variables to serialize.
 * @error: (out)(allow-none): Error return location or #NULL.
 *
 * Returns: New GVariantBuilder with a map of environment key to value strings,
 * or #NULL if there was an error getting the values.
 */
GVariantBuilder *EscalateUtilPamEnvToVariant(pam_handle_t *pamh,
                                             GError **error) {
  char **env_list = NULL;
  GVariantBuilder *builder = NULL;

  env_list = pam_getenvlist(pamh);
  if (!env_list) {
    g_set_error(error, ESCALATE_UTIL_ERROR, ESCALATE_UTIL_ERROR_ENVIRONMENT,
                "Failed to fetch PAM environment list.");
    return NULL;
  }

  builder = g_variant_builder_new(G_VARIANT_TYPE("a{ss}"));
  for (guint i = 0; builder && env_list[i]; i++) {
    gchar **parts = g_strsplit(env_list[i], "=", 2);
    if (parts[0] && parts[1] && strlen(parts[0]) > 0) {
      g_variant_builder_add(builder, "{ss}", parts[0], parts[1]);
    } else {
      g_set_error(error, ESCALATE_UTIL_ERROR, ESCALATE_UTIL_ERROR_ENVIRONMENT,
                  "Failed to parse environment variable '%s'", env_list[i]);
      g_variant_builder_unref(builder);
      builder = NULL;
    }
    g_strfreev(parts);
  }

  for (guint i = 0; env_list[i]; i++) {
    free(env_list[i]);
  }
  free(env_list);

  return builder;
}


/**
 * EscalateUtilPamEnvFromVariant:
 * @pamh: PAM handle where environment variables should be written.
 * @iter: Iterator over environment key/value pairs to write.
 * @error: (out)(allow-none): Error return location or #NULL.
 *
 * Returns: #TRUE if all variables from @iter were written to @pamh.
 */
gboolean EscalateUtilPamEnvFromVariant(pam_handle_t *pamh, GVariantIter *iter,
                                       GError **error) {
  const gchar *key = NULL;
  const gchar *value = NULL;
  gboolean result = TRUE;

  while (result && g_variant_iter_next(iter, "{&s&s}", &key, &value)) {
    gchar *key_and_value = g_strjoin("=", key, value, NULL);
    int pam_result = pam_putenv(pamh, key_and_value);
    if (pam_result != PAM_SUCCESS) {
      g_set_error(error, ESCALATE_UTIL_ERROR, ESCALATE_UTIL_ERROR_ENVIRONMENT,
                  "Failed to set environment variable '%s'", key_and_value);
      result = FALSE;
    }
    g_free(key_and_value);
  }

  g_variant_iter_free(iter);
  return result;
}


GQuark _EscalateUtilErrorQuark() {
  return g_quark_from_string("escalate-util-error-quark");
}
