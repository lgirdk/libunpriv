#ifndef __UTILITY_H
#define __UTILITY_H
#include "cap.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TOKEN_DELIMITER ","

#ifdef _RDK_BROADBAND_PRIV_CAPS_
        #ifdef _COSA_INTEL_XB3_ARM_
                #define LOG_FILE "/rdklogs/logs/CapDebug.txt"
        #elif _COSA_INTEL_USG_ATOM_
                #define LOG_FILE "/rdklogs/logs/CapDebug_atom.txt"
        #else
                #define LOG_FILE "/rdklogs/logs/CapDebug.txt"
        #endif
#elif  defined (_RDK_VIDEO_PRIV_CAPS_)
        #define LOG_FILE "/opt/logs/CapDebug.txt"
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
