#ifndef __UTILITY_H
#define __UTILITY_H
#include "cap.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TOKEN_DELIMITER ","

/*
   Control LOG_FILE via gcc builtin definition __i386__ to avoid the need to
   manually define _RDK_BROADBAND_PRIV_CAPS_ etc from every possible source
   file which may include this header.
*/

#if defined (__i386__)
#define LOG_FILE "/rdklogs/logs/CapDebug_atom.txt"
#else
#define LOG_FILE "/rdklogs/logs/CapDebug.txt"
#endif

/* Read the default,allowed and drop capabilities from CAP_FILE */
void get_capabilities(const char *processname, cap_user *);

/* Logger for libunpriv */
void log_cap(const char * format, ...);

#ifdef __cplusplus
}
#endif
#endif
