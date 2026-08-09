#ifndef DTUN_LOG_H
#define DTUN_LOG_H

#include <stdarg.h>
#include <syslog.h>

#ifdef __cplusplus
extern "C" {
#endif

void dtun_log_init(const char *ident, int use_syslog, const char *facility_str);
void dtun_log_set_syslog(int enable);
int dtun_log_get_syslog(void);
void dtun_log_close(void);

void dtun_vlog(int priority, const char *fmt, va_list ap);
void dtun_log(int priority, const char *fmt, ...);
void dtun_log_info(const char *fmt, ...);
void dtun_log_warn(const char *fmt, ...);
void dtun_log_err(const char *fmt, ...);
void dtun_log_notice(const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif /* DTUN_LOG_H */
