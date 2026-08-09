#include <dtun/log.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static int g_syslog_enabled = 0;
static int g_syslog_opened = 0;
static char g_ident[64] = "dtund";
static int g_facility = LOG_DAEMON;

static int parse_facility(const char *facility_str) {
  if (!facility_str)
    return LOG_DAEMON;
  if (!strcasecmp(facility_str, "daemon"))
    return LOG_DAEMON;
  if (!strcasecmp(facility_str, "user"))
    return LOG_USER;
  if (!strcasecmp(facility_str, "local0"))
    return LOG_LOCAL0;
  if (!strcasecmp(facility_str, "local1"))
    return LOG_LOCAL1;
  if (!strcasecmp(facility_str, "local2"))
    return LOG_LOCAL2;
  if (!strcasecmp(facility_str, "local3"))
    return LOG_LOCAL3;
  if (!strcasecmp(facility_str, "local4"))
    return LOG_LOCAL4;
  if (!strcasecmp(facility_str, "local5"))
    return LOG_LOCAL5;
  if (!strcasecmp(facility_str, "local6"))
    return LOG_LOCAL6;
  if (!strcasecmp(facility_str, "local7"))
    return LOG_LOCAL7;
  if (!strcasecmp(facility_str, "auth") ||
      !strcasecmp(facility_str, "authpriv"))
    return LOG_AUTHPRIV;
  return LOG_DAEMON;
}

void dtun_log_init(const char *ident, int use_syslog,
                   const char *facility_str) {
  if (ident && ident[0] != '\0') {
    strncpy(g_ident, ident, sizeof(g_ident) - 1);
    g_ident[sizeof(g_ident) - 1] = '\0';
  }
  g_facility = parse_facility(facility_str);
  dtun_log_set_syslog(use_syslog);
}

void dtun_log_set_syslog(int enable) {
  if (enable && !g_syslog_opened) {
    openlog(g_ident, LOG_PID | LOG_NDELAY, g_facility);
    g_syslog_opened = 1;
  } else if (!enable && g_syslog_opened) {
    closelog();
    g_syslog_opened = 0;
  }
  g_syslog_enabled = enable;
}

int dtun_log_get_syslog(void) { return g_syslog_enabled; }

void dtun_log_close(void) {
  if (g_syslog_opened) {
    closelog();
    g_syslog_opened = 0;
  }
  g_syslog_enabled = 0;
}

void dtun_vlog(int priority, const char *fmt, va_list ap) {
  char buf[1024];
  va_list ap_copy;

  va_copy(ap_copy, ap);
  vsnprintf(buf, sizeof(buf), fmt, ap_copy);
  va_end(ap_copy);

  size_t len = strlen(buf);
  while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
    buf[--len] = '\0';
  }

  FILE *stream =
      (priority == LOG_ERR || priority == LOG_WARNING ||
       priority == LOG_EMERG || priority == LOG_ALERT || priority == LOG_CRIT)
          ? stderr
          : stdout;
  fprintf(stream, "%s\n", buf);
  fflush(stream);

  if (g_syslog_enabled && g_syslog_opened) {
    syslog(priority, "%s", buf);
  }
}

void dtun_log(int priority, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  dtun_vlog(priority, fmt, ap);
  va_end(ap);
}

void dtun_log_info(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  dtun_vlog(LOG_INFO, fmt, ap);
  va_end(ap);
}

void dtun_log_warn(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  dtun_vlog(LOG_WARNING, fmt, ap);
  va_end(ap);
}

void dtun_log_err(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  dtun_vlog(LOG_ERR, fmt, ap);
  va_end(ap);
}

void dtun_log_notice(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  dtun_vlog(LOG_NOTICE, fmt, ap);
  va_end(ap);
}
