/*
 * ProFTPD - mod_warden
 * Copyright (c) 2011 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 *
 * --- DO NOT EDIT BELOW THIS LINE ---
 */

#include "conf.h"
#include "privs.h"

#define MOD_WARDEN_VERSION		"mod_warden/0.0"

module warden_module;

static int warden_logfd = -1;
static pool *warden_pool = NULL;
static array_header *warden_blacklist = NULL;
static int warden_engine = FALSE;

static const char *trace_channel = "warden";

/* Configuration handlers
 */

/* usage: WardenBlacklist path */
MODRET set_wardenblacklist(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  (void) add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: WardenEngine on|off */
MODRET set_wardenengine(cmd_rec *cmd) {
  int bool = 1;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  bool = get_boolean(cmd, 1);
  if (bool == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = bool;

  warden_engine = bool;
  return PR_HANDLED(cmd);
}

/* usage: WardenLog path|"none" */
MODRET set_wardenlog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  (void) add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* Command handlers
 */

MODRET warden_post_cmd(cmd_rec *cmd) {
  register unsigned int i;
  char **blacklisted_paths;

  if (warden_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  if (session.chroot_path == NULL) {
    /* Not a chrooted session, nothing to do. */
    return PR_DECLINED(cmd);
  }

  if (warden_blacklist == NULL ||
      warden_blacklist->nelts == 0) {
    /* No blacklisted files, nothing to do. */
    return PR_DECLINED(cmd);
  }

  blacklisted_paths = (char **) warden_blacklist->elts;
  for (i = 0; i < warden_blacklist->nelts; i++) {
    int res;
    struct stat st;

    pr_signals_handle();

    pr_trace_msg(trace_channel, 9,
      "%s: checking for blacklisted path '%s'", cmd->argv[0],
      blacklisted_paths[i]);

    pr_fs_clear_cache();
    res = pr_fsio_lstat(blacklisted_paths[i], &st);
    if (res < 0) {
      if (errno != ENOENT) {
        (void) pr_log_writefile(warden_logfd, MOD_WARDEN_VERSION,
          "unable to check blacklisted path '%s': %s", blacklisted_paths[i],
          strerror(errno));

      } else {
        pr_trace_msg(trace_channel, 18,
          "%s: error checking blacklisted path '%s': %s", cmd->argv[0],
          blacklisted_paths[i], strerror(errno));
      }

      continue;
    }

    /* Skip directories, for now. */
    if (S_ISDIR(st.st_mode)) {
      (void) pr_log_writefile(warden_logfd, MOD_WARDEN_VERSION,
        "skipping blacklisted directory '%s'", blacklisted_paths[i]);
      continue;
    }

    res = pr_fsio_unlink(blacklisted_paths[i]);
    if (res < 0) {
      (void) pr_log_writefile(warden_logfd, MOD_WARDEN_VERSION,
        "error unlinking blacklisted path '%s': %s", blacklisted_paths[i],
        strerror(errno));

    } else {
      (void) pr_log_writefile(warden_logfd, MOD_WARDEN_VERSION,
        "deleted blacklisted file '%s'", blacklisted_paths[i]);
      pr_log_pri(PR_LOG_NOTICE, MOD_WARDEN_VERSION
        ": deleted blacklisted file '%s'", blacklisted_paths[i]);
    }
  }

  return PR_DECLINED(cmd);
}

/* Event handlers
 */

#if defined(PR_SHARED_MODULE)
static void warden_mod_unload_ev(const void *event_data, void *user_data) {
  if (strncmp((const char *) event_data, "mod_warden.c", 13) == 0) {

    /* Unregister ourselves from all events. */
    pr_event_unregister(&snmp_module, NULL, NULL);

    destroy_pool(warden_pool);
    warden_pool = NULL;
    warden_blacklist = NULL;

    (void) close(warden_logfd);
    warden_logfd = -1;
  }
}
#endif

static void warden_postparse_ev(const void *event_data, void *user_data) {
  config_rec *c;
  int res;
  char buf[PR_TUNABLE_BUFFER_SIZE+1], *blacklist_path;
  pr_fh_t *blacklist_fh;
  struct stat st;
  unsigned int lineno = 0;

  if (warden_engine == FALSE) {
    return;
  }

  c = find_config(main_server->conf, CONF_PARAM, "WardenLog", FALSE);
  if (c) {
    char *warden_logname;

    warden_logname = c->argv[0];

    if (strncasecmp(warden_logname, "none", 5) != 0) {
      int xerrno;

      pr_signals_block();
      PRIVS_ROOT
      res = pr_log_openfile(warden_logname, &warden_logfd, PR_LOG_SYSTEM_MODE);
      xerrno = errno;
      PRIVS_RELINQUISH
      pr_signals_unblock();

      if (res < 0) {
        if (res == -1) {
          pr_log_pri(PR_LOG_NOTICE, MOD_WARDEN_VERSION
            ": notice: unable to open WardenLog '%s': %s", warden_logname,
            strerror(xerrno));

        } else if (res == PR_LOG_WRITABLE_DIR) {
          pr_log_pri(PR_LOG_NOTICE, MOD_WARDEN_VERSION
            ": notice: unable to open WardenLog '%s': parent directory is "
            "world-writable", warden_logname);

        } else if (res == PR_LOG_SYMLINK) {
          pr_log_pri(PR_LOG_NOTICE, MOD_WARDEN_VERSION
            ": notice: unable to open WardenLog '%s': cannot log to a symlink",
            warden_logname);
        }
      }
    }
  }

  c = find_config(main_server->conf, CONF_PARAM, "WardenBlacklist", FALSE);
  if (c == NULL) {
    (void) pr_log_writefile(warden_logfd, MOD_WARDEN_VERSION,
      "notice: missing required WardenBlacklist directive, disabling module");
    pr_log_pri(PR_LOG_NOTICE, MOD_WARDEN_VERSION
      ": notice: missing required WardenBlacklist directive, disabling module");
    warden_engine = FALSE;
    return;
  }

  /* XXX Use pr_fsio_getline() to read in the Blacklist file contents into.
   * Make sure the warden_blacklist array is allocated.
   */

  blacklist_path = c->argv[0];
  blacklist_fh = pr_fsio_open(blacklist_path, O_RDONLY);
  if (blacklist_fh == NULL) {
    int xerrno = errno;

    (void) pr_log_writefile(warden_logfd, MOD_WARDEN_VERSION,
      "unable to read WardenBlacklist '%s': %s", blacklist_path,
      strerror(xerrno));
    pr_log_pri(PR_LOG_NOTICE, MOD_WARDEN_VERSION
      ": unable to read WardenBlacklist '%s': %s", blacklist_path,
      strerror(xerrno));
    return;
  }

  /* Stat the opened file to determine the optimal buffer size for IO. */
  memset(&st, 0, sizeof(st));
  if (pr_fsio_fstat(blacklist_fh, &st) == 0) {
    blacklist_fh->fh_iosz = st.st_blksize;
  }

  memset(buf, '\0', sizeof(buf));
  while (pr_fsio_getline(buf, sizeof(buf)-1, blacklist_fh, &lineno) != NULL) {
    int have_eol = FALSE;
    size_t buflen;
    char cleaned_path[PR_TUNABLE_BUFFER_SIZE+1];

    pr_signals_handle();

    buflen = strlen(buf);

    /* Trim off the trailing newline, if present. */
    if (buflen &&
        buf[buflen-1] == '\n') {
      have_eol = TRUE;
      buf[buflen-1] = '\0';
      buflen = strlen(buf);
    }

    while (buflen &&
           buf[buflen - 1] == '\r') {
      pr_signals_handle();
      buf[buflen-1] = '\0';
      buflen = strlen(buf);
    }

    if (!have_eol) {
      (void) pr_log_writefile(warden_logfd, MOD_WARDEN_VERSION,
        "warning: handling possibly truncated blacklisted file at "
        "line %u of '%s'", lineno, blacklist_fh->fh_path);
    }

    if (buf[0] != '/') {
      (void) pr_log_writefile(warden_logfd, MOD_WARDEN_VERSION,
        "warning: blacklisted file '%s' (at line %u of '%s') not an "
        "absolute path, skipping", buf, lineno, blacklist_fh->fh_path);
      continue;
    }

    memset(cleaned_path, '\0', sizeof(cleaned_path));
    pr_fs_clean_path(buf, cleaned_path, sizeof(cleaned_path)-1);

    if (warden_blacklist == NULL) {
      warden_blacklist = make_array(warden_pool, 4, sizeof(char **));
    }

    pr_trace_msg(trace_channel, 4, "adding blacklisted path '%s' to the list",
      cleaned_path);
    *((char **) push_array(warden_blacklist)) = pstrdup(warden_pool,
      cleaned_path);
  }

  pr_fsio_close(blacklist_fh);

  if (warden_blacklist != NULL) {
    (void) pr_log_writefile(warden_logfd, MOD_WARDEN_VERSION,
      "watching for %u blacklisted %s", warden_blacklist->nelts,
      warden_blacklist->nelts != 1 ? "files" : "file");
  }
}

static void warden_restart_ev(const void *event_data, void *user_data) {
  if (warden_engine == FALSE) {
    return;
  }

  destroy_pool(warden_pool);
  warden_blacklist = NULL;

  (void) close(warden_logfd);

  warden_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(warden_pool, MOD_WARDEN_VERSION);
}

static void warden_shutdown_ev(const void *event_data, void *user_data) {

  destroy_pool(warden_pool);
  warden_pool = NULL;
  warden_blacklist = NULL;

  if (warden_logfd >= 0) {
    (void) close(warden_logfd);
    warden_logfd = -1;
  }
}

/* Initialization routines
 */

static int warden_init(void) {
  warden_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(warden_pool, MOD_WARDEN_VERSION);

#if defined(PR_SHARED_MODULE)
  pr_event_register(&warden_module, "core.module-unload", warden_mod_unload_ev,
    NULL);
#endif
  pr_event_register(&warden_module, "core.postparse", warden_postparse_ev,
    NULL);
  pr_event_register(&warden_module, "core.restart", warden_restart_ev, NULL);
  pr_event_register(&warden_module, "core.shutdown", warden_shutdown_ev, NULL);

  return 0;
}

static int warden_sess_init(void) {
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "WardenEngine", FALSE);
  if (c) {
    warden_engine = *((int *) c->argv[0]);
  }

  return 0;
}

/* Module API tables
 */

static conftable warden_conftab[] = {
  { "WardenBlacklist",	set_wardenblacklist,	NULL },
  { "WardenEngine",	set_wardenengine,	NULL },
  { "WardenLog",	set_wardenlog,		NULL },
  { NULL }
};

static cmdtable warden_cmdtab[] = {
  { POST_CMD,		C_PASS,	G_NONE,	warden_post_cmd,	FALSE,	FALSE },
  { POST_CMD,		C_RNTO,	G_NONE,	warden_post_cmd,	FALSE,	FALSE },
  { POST_CMD,		C_SITE,	G_NONE,	warden_post_cmd,	FALSE,	FALSE },
  { POST_CMD,		C_STOR,	G_NONE,	warden_post_cmd,	FALSE,	FALSE },

  { 0, NULL }
};

module warden_module = {
  /* Always NULL */
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "warden",

  /* Module configuration handler table */
  warden_conftab,

  /* Module command handler table */
  warden_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization */
  warden_init,

  /* Session initialization */
  warden_sess_init,

  /* Module version */
  MOD_WARDEN_VERSION
};

