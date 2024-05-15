#include "utility.h"
#include <iostream>
#include <json/json.h>
#include <json/value.h>
#include <fstream>
#include <algorithm>
#include <cctype>
#include <cstdarg>
#include <time.h>

using namespace std;
const string m_sCapFileName = "/etc/security/caps/process-capabilities.json";

const std::string currentDateTime()
{
    struct timespec ts;
    memset(&ts, 0, sizeof(ts));
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm * tstruct = gmtime( &ts.tv_sec );
    char       buf[80];
    char       outBuf[80];

    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", tstruct);
    snprintf(outBuf, sizeof(outBuf), "%s.%03dZ ", buf, (int)(ts.tv_nsec/1000000));

    return outBuf;
}

int _vscprintf (const char * format, va_list pargs) {
      int retval;
      va_list argcopy;
      va_copy(argcopy, pargs);
      retval = vsnprintf(NULL, 0, format, argcopy)+1;
      va_end(argcopy);
      return retval;
}

void log_cap(const char * format, ...)
{
    ofstream m_Logfile;
    m_Logfile.open(LOG_FILE, ios::out | ios::app);

    char* sMessage = NULL;
    int nLength = 0;
    va_list args;

    va_start(args, format);
    nLength = _vscprintf(format, args);
    sMessage = new char[nLength];
    vsnprintf(sMessage, nLength, format, args);

    m_Logfile << currentDateTime() << ":[non-root]: " <<sMessage;
    va_end(args);
    m_Logfile.close();

    delete [] sMessage;
}

inline std::string& trim(std::string& args)
{
    args.erase(std::remove_if(args.begin(),args.end(),[](char &c) {
          return !(isalnum(c) || (c == '_') || (c == ','));}),args.end());
    return args;
}

void populate_capabilities(Json::Value cfg_root, std::string caps_list, cap_value_t* appcaps_list,short int* cap_count){
    std::string str_tmp;
    cap_value_t val;
    trim(caps_list);

    std::size_t start = caps_list.find_first_not_of(TOKEN_DELIMITER), end = start;
    while (start != string::npos)
    {
      end = caps_list.find(TOKEN_DELIMITER,start);
      str_tmp.assign(caps_list.substr(start,(end == string::npos) ? string::npos : end - start));
      if(cap_from_name(str_tmp.c_str(),&val) < 0 ){
        std::string group_list = cfg_root[str_tmp].asString();
        if(!group_list.empty()){
           populate_capabilities(cfg_root,group_list,appcaps_list,cap_count);
        }
      }
      else{
           appcaps_list[*cap_count] = val;
           (*cap_count)++;
      }
      start = caps_list.find_first_not_of(TOKEN_DELIMITER,end);
    }
}

void get_capabilities(const char *processname, cap_user *appcaps)
{
    Json::Value cfg_root;
    std::ifstream cfgfile(m_sCapFileName.c_str());
    
    if (!cfgfile) {
       log_cap("get_capabilities failed to open file \n");
       exit(1);   
    }

    cfgfile >> cfg_root;

    std::string default_caps = cfg_root["default"].asString();
    if(!default_caps.empty()){
       populate_capabilities(cfg_root,default_caps,appcaps->caps_default,&appcaps->default_count);
    }

    std::string allow_caps = cfg_root[processname]["allow"].asString();
    if(!allow_caps.empty()){
       populate_capabilities(cfg_root,allow_caps,appcaps->add,&appcaps->add_count);
    }

    std::string drop_caps = cfg_root[processname]["drop"].asString();
    if(!drop_caps.empty()){
       populate_capabilities(cfg_root,drop_caps,appcaps->drop,&appcaps->drop_count);
    }
}
