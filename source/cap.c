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
#define _GNU_SOURCE
#include "cap.h"
#include "utility.h"
#include <string.h>

static cap_t caps;

static void get_process_name(const pid_t pid, char *pname);

#define BLOCKLIST_RFC "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.NonRootSupport.Blocklist"
#ifdef _COSA_INTEL_XB3_ARM_
    #define BLOCKLIST_FILE "/nvram/Blocklist_XB3.txt"
#elif defined _COSA_INTEL_USG_ATOM_
    #define BLOCKLIST_FILE "/nvram/Blocklist_XB3.txt"
#else
    #define BLOCKLIST_FILE "/opt/secure/Blocklist_file.txt"
#endif

/* prepare and updated caps list */
bool isNull(char *str)
{
 if(str == NULL || str[0] == '\0')
 {
   return true;
 }
 return false;
}

bool fetchRFC(char* key,char** value)
{
#ifdef _RDK_VIDEO_PRIV_CAPS_
 RFC_ParamData_t nonrootsupportData;
 WDMP_STATUS nonrootstatus= getRFCParameter("NonRootSupport",key, &nonrootsupportData);
  if (WDMP_SUCCESS == nonrootstatus && (!isNull(nonrootsupportData.value)))
  {
     *value = (char*)malloc(strlen(nonrootsupportData.value)+1);
     if( NULL != *value ){
        strncpy(*value,nonrootsupportData.value,strlen(nonrootsupportData.value)+1);
        return true;
     }
  }
#endif
  return false;
}

bool isBlocklisted()
{
  bool ret=false;
#ifdef _RDK_BROADBAND_PRIV_CAPS_
  FILE *fp = NULL;
  int len=0;
  char process_name[64]={'\0'};
  char *buf = NULL;
  fp = fopen(BLOCKLIST_FILE,"r");
  if(fp == NULL)
  {
    return ret;
  }
  fseek(fp, 0, SEEK_END);
  len = ftell(fp);
  if(len >= 0)
  {
    fseek(fp, 0, SEEK_SET);
    buf = (char*)malloc(sizeof(char) * (len + 1));
    if (buf != NULL)
    {
      memset(buf, 0, (sizeof(char) * (len + 1)));
      fread(buf, 1, len, fp);
      buf[len] = '\0';
    }
    else
    {
      log_cap("Memory allocation failed for buffer\n");
    }
    fclose(fp);
    if((buf != NULL) && (strlen(buf) != 0)){
      get_process_name(getpid(), process_name);
      if(strcasestr(buf,process_name) != NULL) {
        log_cap("process[%s] is found in blocklist,thus process runs in Root mode\n",process_name);
        ret = true;
      }
      free(buf);
      buf = NULL;
    }
  }
#elif _RDK_VIDEO_PRIV_CAPS_
 char *list=NULL;
 char process_name[64]={'\0'};
 if(fetchRFC(BLOCKLIST_RFC,&list))
 {
    get_process_name(getpid(), process_name);
    if(strcasestr(list,process_name) != NULL)
    {
       log_cap("process[%s] is found in blocklist,Thus process runs in Root mode\n",process_name);
       ret = true;
    }
 }
 if(list)
 {
     free(list); // CID 192628 Resource leak (RESOURCE_LEAK)
     list = NULL;
 }
#endif
 return ret;
}

void prepare_caps(cap_user *_appcaps,const cap_value_t _cap_add[],const cap_value_t _cap_drop[])
{
    int i=0;
    const char *default_user = "non-root";
    if ( _appcaps == NULL )  {
         log_cap("Failed to allocate cap_user: \n");
         exit(1);
    }
    if ( _cap_add != NULL )  {
         for ( i = 0; i < _appcaps->add_count ; i++)  {
                _appcaps->add[i]= _cap_add[i];
         }
    }
    if ( _cap_drop != NULL )  {
         for ( i = 0; i < _appcaps->drop_count ; i++)  {
                _appcaps->drop[i]= _cap_drop[i];
         }
    }
    if (_appcaps->user_name)  {
       strncpy(_appcaps->user_name, default_user, strlen(default_user)+1);
    }
}

static void get_process_name(const pid_t pid, char *pname)
{
  char procfile[32]={'\0'};
  sprintf(procfile, "/proc/%d/comm", pid);
  FILE* fp = fopen(procfile, "r");
  if (fp) {
        size_t size;
        size = fread(pname, sizeof (char), sizeof (procfile), fp);
        if (size > 0) {
            if ('\n' == pname[size - 1])
		  pname[size - 1] = '\0';
	}
        fclose(fp);
  }
}

/*check if process is already running as non-root*/
bool isNonroot( )
{
   return ((getuid()!=0)?true:false);
}

/* initializes cap_t structure */
cap_t init_capability(void)
{
   caps = cap_get_proc();
   if (caps == NULL)
   {
     log_cap("Capabilities not available \n");
   }
   return caps;
}
/* Dumping user define structure and current capability of process */
void read_capability(cap_user *_appcaps)
{
   caps = cap_get_pid(getpid());
   if (caps == NULL)
   {
       log_cap("Failed to get current caps for %d process \n", getpid());
       exit(1);
   }
   if (_appcaps != NULL)  {
       log_cap("unprivilege user name: %s \n", _appcaps->user_name);
   
       if (_appcaps->caps != NULL) { //CID 143594: Dereference after null check (FORWARD_NULL)
           cap_free(_appcaps->caps);
       }
       _appcaps->caps = cap_to_text(caps, NULL);
       if (_appcaps->caps == NULL)  {
           log_cap("Unable to handle error in cap_to_text \n");
           exit(1);
       }
   log_cap("Dumping current caps of the process: %s\n", _appcaps->caps);
   cap_free(caps);
   }
}

void set_ambient_caps( const cap_value_t caplist[],short count,cap_flag_value_t value)
{
    int i,retval=-1;
    /* Make sure the inheritable set is preserved across execve via the ambient set*/
    for ( i = 0; i < count ; i++) {
        retval = cap_set_ambient(caplist[i],value);
        if (retval != 0) {
            char *amb_ptr;
            amb_ptr = cap_to_name(caplist[i]);
            log_cap("Unable to raise/lower ambient capability [%s]\n", amb_ptr);
            cap_free(amb_ptr);
        }
    }
}

/* Identify the list of capabilities which need to set while run as non-root;
   capabilities will be changed based on the application
   Few capabilities can be added/droped by an application          */
int drop_root_caps(cap_user *_appcaps)
{
   int retval=-1;
   struct passwd *ent_pw = NULL;
   const char *default_user = "non-root";
   char process_name[64]={'\0'};
   get_process_name(getpid(), process_name);

   if(isNonroot()) {
      log_cap("No need to drop_root_caps again - %s process is already running as non-root\n",process_name);
      return 0;
   }

   if (_appcaps->user_name == NULL)  {
       _appcaps->user_name = (char*)malloc(strlen(default_user)+1);
       if( NULL != _appcaps->user_name ){
           strncpy(_appcaps->user_name,default_user,strlen(default_user)+1);
       }
   }
   
   
   get_capabilities(process_name, _appcaps);

   prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);
   if(getuid() == 0)  {
      if( NULL != _appcaps->user_name ) // CID 160956: Dereference after null check (FORWARD_NULL)
      ent_pw = getpwnam(_appcaps->user_name);
      if (ent_pw && ent_pw->pw_uid != 0) {
          if (setgid(ent_pw->pw_gid) < 0) {
              log_cap("setgid(): failed \n");
              return retval;
          }
          if (setuid(ent_pw->pw_uid) < 0) {
              log_cap("setuid(): failed");
              return retval;
          }
      }
   }

   /* Restrict the permitted set such that it contains only the default and process-specific allow capabilities */
   if (cap_clear_flag(caps, CAP_PERMITTED)) {
        log_cap("PERMITTED - cap_clear_flag() internal error\n");
   }
   if ( (cap_set_flag(caps, CAP_PERMITTED,  _appcaps->default_count, _appcaps->caps_default, CAP_SET) < 0) ) {
        log_cap("Unable to set default PERMITTED Flags\n");
   }
   if ( _appcaps->add_count > 0 )  {
     if (cap_set_flag(caps, CAP_PERMITTED, (_appcaps->add_count), _appcaps->add, CAP_SET) < 0)
     {
         log_cap("Unable to set process specific PERMITTED Flags\n");
     }
   }

   if (cap_clear_flag(caps, CAP_EFFECTIVE)) {
        log_cap("EFFECTIVE - cap_clear_flag() internal error\n");
   }
   if ( (cap_set_flag(caps, CAP_EFFECTIVE,  _appcaps->default_count, _appcaps->caps_default, CAP_SET) < 0) ) {
        log_cap("Unable to set default EFFECTIVE Flags\n");
   }
   if ( (cap_set_flag(caps, CAP_INHERITABLE,  _appcaps->default_count, _appcaps->caps_default, CAP_SET) < 0) ) {
        log_cap("Unable to set default INHERITABLE Flags\n");
   }
   retval = cap_set_proc(caps);
   if (retval == -1)  {
        log_cap("Failed to set default capabilities\n");
        return retval;
   }

   if (CAP_AMBIENT_SUPPORTED()) {
       set_ambient_caps(_appcaps->caps_default,_appcaps->default_count,CAP_SET);
   }
   log_cap("Dropping root privilege of %s: runs as unprivilege mode\n", process_name);
   return retval;
}

int update_process_caps(cap_user *_appcaps)
{
   int retval=-1;
   char process_name[64]={'\0'};
   if ( _appcaps->add_count > 0 )  {
     if (cap_set_flag(caps, CAP_EFFECTIVE, (_appcaps->add_count), _appcaps->add, CAP_SET) < 0)
     {
         log_cap("Unable to set process specific EFFECTIVE Flags\n");
     }
     if (cap_set_flag(caps, CAP_INHERITABLE, (_appcaps->add_count), _appcaps->add, CAP_SET) < 0)
     {
         log_cap("Unable to set process specific INHERITABLE Flags\n");
     }
   }
   if ( _appcaps->drop_count > 0 ) {
     if (cap_set_flag(caps, CAP_PERMITTED, (_appcaps->drop_count), _appcaps->drop, CAP_CLEAR) < 0)
     {
         log_cap("Unable to clear process specific PERMITTED Flags\n");
     }
     if (cap_set_flag(caps, CAP_EFFECTIVE, (_appcaps->drop_count), _appcaps->drop, CAP_CLEAR) < 0)
     {
         log_cap("Unable to clear process specific EFFECTIVE Flags\n");
     }
     if(cap_set_flag(caps, CAP_INHERITABLE, (_appcaps->drop_count), _appcaps->drop, CAP_CLEAR) < 0) 
     {
         log_cap("Unable to clear process specific INHERITABLE Flags\n");
     }
   }
   retval = cap_set_proc(caps);
   if (retval == -1)  {
        log_cap("Failed to set process specific capabilities\n");
        return retval;
   }
   prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);

   if (CAP_AMBIENT_SUPPORTED()) {
       if ( _appcaps->add_count > 0 )  {
           set_ambient_caps(_appcaps->add,_appcaps->add_count,CAP_SET);
       }
       if ( _appcaps->drop_count > 0 ) {
           set_ambient_caps(_appcaps->drop,_appcaps->drop_count,CAP_CLEAR);
       }
   }

   get_process_name(getpid(), process_name);
   cap_free(caps);
   caps = NULL;
   return retval;
}


bool drop_root_priv(cap_user *_appcaps)
{
    bool ret = false;
    if(init_capability() != NULL) {
        if(drop_root_caps(_appcaps) != -1) {
            if(update_process_caps(_appcaps) != -1) {
                read_capability(_appcaps);
                ret = true;
            }
        }
    }
    return ret;
}

void gain_root_privilege()
{
  if (setgid(0) == -1) {
    log_cap(" setting setgid(): failed \n");
    exit(1);
   }
  if (setuid(0) < 0) {
    log_cap("setting setuid(): failed");
    exit(1);
  }
}

