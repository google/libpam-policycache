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

#include <glib.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static gboolean do_auth = FALSE;
static gboolean do_session = FALSE;
static gchar *service_name = "login";
static gchar *username = NULL;
static int setcred_style = PAM_ESTABLISH_CRED;
static gchar **use_env = NULL;
static gboolean do_setuid = FALSE;
static gboolean do_setgid = FALSE;


static gboolean HandleSetcredStyle(const gchar *option_name, const gchar *value,
                                   gpointer group_data, GError **error) {
  if (g_str_equal(value, "establish")) {
    setcred_style = PAM_ESTABLISH_CRED;
    return TRUE;
  } else if (g_str_equal(value, "delete")) {
    setcred_style = PAM_DELETE_CRED;
    return TRUE;
  } else if (g_str_equal(value, "reinit")) {
    setcred_style = PAM_REINITIALIZE_CRED;
    return TRUE;
  } else if (g_str_equal(value, "refresh")) {
    setcred_style = PAM_REFRESH_CRED;
    return TRUE;
  } else {
    g_set_error(error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
                "Unknown pam_setcred() flag '%s'", value);
    return FALSE;
  }
}


static GOptionEntry entries [] = {
  { "auth", 0, 0, G_OPTION_ARG_NONE, &do_auth,
    "Do pam_authenticate()", NULL },
  { "setcred-style", 0, 0, G_OPTION_ARG_CALLBACK, HandleSetcredStyle,
    "Flag for pam_setcred(): establish*, delete, reinit, or refresh", "FLAG" },
  { "session", 0, 0, G_OPTION_ARG_NONE, &do_session,
    "Do pam_*_session()", NULL },
  { "service", 0, 0, G_OPTION_ARG_STRING, &service_name,
    "Service name given to pam_start()", "SERVICE" },
  { "username", 0, 0, G_OPTION_ARG_STRING, &username,
    "Username given to pam_start()", "USER" },
  { "env", 0, 0, G_OPTION_ARG_STRING_ARRAY, &use_env,
    "Environment variables and optional values to use", "KEY=VALUE" },
  { "setuid", 0, 0, G_OPTION_ARG_NONE, &do_setuid,
    "If run with euid=0, call setuid(0)", NULL },
  { "setgid", 0, 0, G_OPTION_ARG_NONE, &do_setgid,
    "If run with egid=0, call setgid(0)", NULL },
  { NULL },
};


int HandleConversation(int messages_len, const struct pam_message **messages,
                       struct pam_response **responses_p, void *appdata_ptr) {
  char *response = NULL;
  char line[LINE_MAX];
  struct pam_response *responses = NULL;
  g_assert(messages_len == 1);
  switch (messages[0]->msg_style) {
    case PAM_PROMPT_ECHO_OFF:
      response = strdup(getpass(messages[0]->msg));
      break;
    case PAM_PROMPT_ECHO_ON:
      g_print("%s", messages[0]->msg);
      g_assert(fgets(line, LINE_MAX, stdin));
      response = strdup(line);
    case PAM_ERROR_MSG:
      g_print("Error: %s\n", messages[0]->msg);
      break;
    case PAM_TEXT_INFO:
      g_print("Info: %s\n", messages[0]->msg);
      break;
    default:
      g_error("Unknown message style");
  }

  responses = malloc(sizeof(struct pam_response));
  responses[0].resp = response;
  responses[0].resp_retcode = 0;
  *responses_p = responses;
  return PAM_SUCCESS;
}


gboolean PrintPamInfo(pam_handle_t *pamh) {
  char **env_lines = NULL;
  g_print("Environment variables:\n");
  env_lines = pam_getenvlist(pamh);
  g_assert(env_lines);
  if (!env_lines[0]) {
    g_print("  <none>\n");
  }
  for (guint i = 0; env_lines[i]; i++) {
    g_print("  %s\n", env_lines[i]);
    free(env_lines[i]);
  }
  free(env_lines);
  g_print("\n");
  return TRUE;
}


int main(int argc, char **argv) {
  GError *error = NULL;
  GOptionContext *context = NULL;
  struct pam_conv conversation = { HandleConversation, NULL };
  pam_handle_t *pamh;
  int pam_result = 0;
  int exit_code = 2;

  context = g_option_context_new("- test the live PAM stack");
  g_option_context_add_main_entries(context, entries, NULL);
  if (!g_option_context_parse(context, &argc, &argv, &error)) {
    g_printerr("Failed to parse command-line options: %s\n", error->message);
    goto done;
  }

  if (!username) {
    username = g_strdup(g_get_user_name());
  }

  if (!do_auth && !do_session) {
    do_auth = TRUE;
  }

  if (getuid() != geteuid()) {
    g_print("Running with setuid bit set\n");
    if (do_setuid) {
      g_printerr("setuid(%d)\n", geteuid());
      g_assert(setuid(geteuid()) == 0);
    }
  }

  if (getgid() != getegid()) {
    g_print("Running with setgid bit set\n");
    if (do_setgid) {
      g_printerr("setgid(%d)\n", getegid());
      g_assert(setgid(getegid()) == 0);
    }
  }

  g_print("pam_start('%s', '%s', ...)\n", service_name, username);
  pam_result = pam_start(service_name, username, &conversation, &pamh);
  if (pam_result) {
    goto done;
  }

  if (use_env && use_env[0]) {
    g_print("pam_putenv(pamh, ...)\n");
  }
  for (guint i = 0; use_env && use_env[i]; i++) {
    if (strstr(use_env[i], "=")) {
      pam_result = pam_putenv(pamh, use_env[i]);
    } else {
      gchar *env_line = g_strdup_printf("%s=%s", use_env[i],
                                        getenv(use_env[i]));
      pam_result = pam_putenv(pamh, env_line);
      g_free(env_line);
    }

    if (pam_result) {
      goto pam_done;
    }
  }
  PrintPamInfo(pamh);

  if (do_auth) {
    g_print("pam_authenticate(pamh, 0)\n");
    pam_result = pam_authenticate(pamh, 0);
    if (pam_result) {
      goto pam_done;
    }
    PrintPamInfo(pamh);

    g_print("pam_setcred(pamh, %d)\n", setcred_style);
    pam_result = pam_setcred(pamh, setcred_style);
    if (pam_result) {
      goto pam_done;
    }
    PrintPamInfo(pamh);
  }

  if (do_session) {
    g_print("pam_open_session(pamh, 0)\n");
    pam_result = pam_open_session(pamh, 0);
    if (pam_result) {
      g_printerr("pam_open_session() failed: %s\n",
                 pam_strerror(pamh, pam_result));
      goto pam_done;
    }
    PrintPamInfo(pamh);

    g_print("pam_close_session(pamh, 0)\n");
    pam_result = pam_close_session(pamh, 0);
    if (pam_result) {
      g_printerr("pam_close_session() failed: %s\n",
                 pam_strerror(pamh, pam_result));
      goto pam_done;
    }
    PrintPamInfo(pamh);
  }

  g_print("Success!\n");
  exit_code = 0;

pam_done:
  g_assert(pam_end(pamh, pam_result) == PAM_SUCCESS);

done:
  if (pam_result) {
    g_printerr("Failed with PAM result: %s (%d)\n",
               pam_strerror(pamh, pam_result), pam_result);
    exit_code = 1;
  }
  return exit_code;
}
