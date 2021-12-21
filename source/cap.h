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
#ifdef _RDK_VIDEO_PRIV_CAPS_
#include "rfcapi.h"
#endif
#ifdef __cplusplus
extern "C" {
#endif

typedef struct _cap_user {
cap_value_t add[CAP_LAST_CAP+1];
cap_value_t drop[CAP_LAST_CAP+1];
cap_value_t caps_default[CAP_LAST_CAP+1];
char *user_name;
short add_count;
short drop_count;
short default_count;
char *caps;
}cap_user;

// check for blocklist process
bool isBlocklisted(void);

// fetch the blocklist rfc
bool fetchRFC(char* key,char** value);

/* initializes cap_t structure */
cap_t init_capability(void);

/* Application/Process specific capabilities */
void prepare_caps(cap_user *,const cap_value_t cap_add[], const cap_value_t cap_drop[]);

/* Identify the list of capabilities which need to set while run as non-root;
   Default capabilities will be applied from this function */
int drop_root_caps(cap_user *);

/* Applying process/application specific capabilities */
int update_process_caps(cap_user *);

/* Read the current capability of process */
void read_capability(cap_user *);

/* Switch to non-root */
bool drop_root_priv(cap_user *);

/* Switch to root */
void gain_root_privilege();

void get_capabilities(const char *processname, cap_user *);

void log_cap(const char * format, ...);
#ifdef __cplusplus
}
#endif

#endif //CAP_H_

