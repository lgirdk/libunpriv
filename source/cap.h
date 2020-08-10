/*
 * If not stated otherwise in this file or this component's Licenses.txt
 * file the following copyright and licenses apply:
 *
 * Copyright 2018 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
#ifndef CAP_H_
#define CAP_H_

#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <pwd.h>
#include <errno.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

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
        #define LOG_FILE "/tmp/CapDebug.txt"
#endif
#define log_cap(x...)  { \
    FILE *fp = fopen(LOG_FILE, "a+"); \
    struct tm *local; \
    time_t t; \
    t = time(NULL); \
    local = gmtime(&t); \
    char *tempTime = asctime(local); \
    tempTime[ strlen(tempTime) - 1 ] = '\0'; \
    if (fp != NULL) {  \
        fprintf(fp,"%s[non-root]:",tempTime); \
        fprintf(fp,## x); \
        fclose(fp);  \
    }                \
}while(0) \

typedef struct _cap_user {
cap_value_t add[CAP_LAST_CAP+1];
cap_value_t drop[CAP_LAST_CAP+1];
char user_name[16];
short add_count;
short drop_count;
char *caps;
}cap_user;

cap_t caps;

/* initializes cap_t structure */
cap_t init_capability(void);

/* Application/Process specific capabilities */
void prepare_caps(cap_user *,const cap_value_t cap_add[], const cap_value_t cap_drop[]);

/* Identify the list of capabilities which need to set while run as non-root;
   Default capabilities will be applied from this function */
void drop_root_caps(cap_user *);

/* Applying process/application specific capabilities */
int update_process_caps(cap_user *); 

/* Read the current capability of process */
void read_capability(cap_user *);

/* Switch to root */
void gain_root_privilege();
#ifdef __cplusplus
}
#endif
  
#endif //CAP_H_   
