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
#include "cap.h"
/* prepare and updated caps list */
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
    strncpy(_appcaps->user_name, default_user,sizeof(_appcaps->user_name));
}
void get_process_name(const pid_t pid, char *pname)
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
  log_cap("Dropping root privilege of %s: runs as unprivilege mode\n", pname);
}
/* initializes cap_t structure */
cap_t init_capability(void)
{
   caps = cap_get_proc();
   if (caps == NULL)
   {
     log_cap("Capabilities not available \n");
     exit(1);
   }
   return caps;
}
/* Dumping user define structure and current capability of process */
void read_capability(cap_user *_appcaps)
{
   caps = cap_get_pid(getpid());
   if (caps == NULL)
   {
       log_cap("Failed to get current caps for %s process \n", getpid());
       exit(1);
   }
   if (_appcaps != NULL)  {
       log_cap("unprivilege user name: %s \n", _appcaps->user_name);
   }
   if (_appcaps->caps != NULL) {
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
/* Identify the list of capabilities which need to set while run as non-root;
   capabilities will be changed based on the application
   Few capabilities can be added/droped by an application          */
void drop_root_caps(cap_user *_appcaps)
{
   int retval=-1,def_count=0,i=0,amb_retval=-1;
   struct passwd *ent_pw = NULL;
   const cap_value_t caps_default[] = {CAP_CHOWN,CAP_DAC_OVERRIDE,CAP_DAC_READ_SEARCH,CAP_FOWNER,CAP_FSETID,CAP_LINUX_IMMUTABLE,CAP_NET_BIND_SERVICE,CAP_NET_BROADCAST,CAP_NET_ADMIN,CAP_NET_RAW,CAP_IPC_LOCK,CAP_IPC_OWNER,CAP_SYS_CHROOT,CAP_SYS_PTRACE,CAP_SETPCAP,CAP_SYS_RESOURCE,CAP_SYS_ADMIN,CAP_SYS_BOOT,CAP_SYS_NICE,CAP_SETFCAP,CAP_SYS_TTY_CONFIG,CAP_SYS_RAWIO,CAP_SETGID,CAP_SETUID};
 
   prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);    
   def_count = sizeof(caps_default)/sizeof(int);
   if(getuid() == 0)  {
      ent_pw = getpwnam(_appcaps->user_name);
      if (ent_pw && ent_pw->pw_uid != 0)  {
          if (setgid(ent_pw->pw_gid) == -1)   {
                  log_cap("setgid(): failed \n");
              }
          }
          if (setuid(ent_pw->pw_uid) < 0) {
              log_cap("setuid(): failed"); 
              exit(1);
          }     
   }
   if (cap_clear_flag(caps, CAP_EFFECTIVE)) {
       log_cap("cap_clear_flag() internal error \n");
   }
   if ( (cap_set_flag(caps, CAP_EFFECTIVE, def_count, caps_default, CAP_SET) < 0) ) {
         log_cap("Unable to set default EFFECTIVE Flags: \n");
   }
   if ( (cap_set_flag(caps, CAP_INHERITABLE, def_count, caps_default, CAP_SET) < 0) ) {
         log_cap("Unable to set default INHERITABLE Flags: \n");
   }
   retval = cap_set_proc(caps);
   if (retval == -1)  {
        log_cap("Failed to set default capabilities \n");
        exit(1);
   }
  
   if (CAP_AMBIENT_SUPPORTED()) {
       /* Make sure the inheritable set is preserved across execve via the ambient set */   
       for ( i = 0; i < def_count ; i++) {
	    amb_retval = cap_set_ambient(caps_default[i],CAP_SET);
            if (amb_retval != 0) {
	        char *amb_name_ptr;
	        amb_name_ptr = cap_to_name(caps_default[i]);
	        log_cap("Unable to raise ambient capability [%s]\n", amb_name_ptr);
	        cap_free(amb_name_ptr);
 	    }
       }
   }
}
int update_process_caps(cap_user *_appcaps)
{
   int retval=-1,i=0, j=0, amb_retval=-1;
   char process_name[64]={'\0'};
   if ( _appcaps->add_count > 0 )  {
     if (cap_set_flag(caps, CAP_EFFECTIVE, (_appcaps->add_count), _appcaps->add, CAP_SET) < 0)
     {
         log_cap("Unable to set process specific EFFECTIVE Flags \n");
     }
     if (cap_set_flag(caps, CAP_INHERITABLE, (_appcaps->add_count), _appcaps->add, CAP_SET) < 0)
     {
         log_cap("Unable to set process specific INHERITABLE Flags \n");
     }
   }   
   if ( _appcaps->drop_count > 0 ) {
     if (cap_set_flag(caps, CAP_EFFECTIVE, (_appcaps->drop_count), _appcaps->drop, CAP_CLEAR) < 0)
     { 
         log_cap("Unable to clear process specific EFFECTIVE Flags \n");
     }
     if(cap_set_flag(caps, CAP_INHERITABLE, (_appcaps->drop_count), _appcaps->drop, CAP_CLEAR) < 0) 
     {
         log_cap("Unable to clear process specific INHERITABLE Flags \n");
     }
   }  
   retval = cap_set_proc(caps);
   if (retval == -1)  {
        log_cap("Failed to set process specific capabilities: \n");
        exit(1);
   }
   prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
  
   if (CAP_AMBIENT_SUPPORTED()) {
       if ( _appcaps->add_count > 0 )  {
           for ( i = 0; i < _appcaps->add_count ; i++)  {
               amb_retval = cap_set_ambient(_appcaps->add[i],CAP_SET);
               if (amb_retval != 0) {
                   char *amb_name_ptr;
                   amb_name_ptr = cap_to_name(_appcaps->add[i]);
                   log_cap("Unable to raise ambient capability [%s]\n", amb_name_ptr);
                   cap_free(amb_name_ptr);
               }
           }
       }   

       if ( _appcaps->drop_count > 0 )  {
           for ( j = 0; j < _appcaps->drop_count ; j++)  {
               amb_retval = cap_set_ambient(_appcaps->drop[j],CAP_CLEAR);
               if (amb_retval != 0) {
                   char *amb_name_ptr;
                   amb_name_ptr = cap_to_name(_appcaps->drop[j]);
                   log_cap("Unable to lower ambient capability [%s]\n", amb_name_ptr);
                   cap_free(amb_name_ptr);
               }
           }
      }
   }
   get_process_name(getpid(), process_name);
   cap_free(caps);
   caps = NULL;
   return retval;   
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
