##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2018 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################
AM_CFLAGS=$(TRACE_CFLAGS) $(LIBCAP_CFLAGS) 
AM_CXXFLAGS = -Wall -std=c++1y
lib_LTLIBRARIES = libprivilege.la
libprivilege_la_SOURCES = cap.c utility.cpp
libprivilege_la_LDFLAGS =$(TRACE_LIBS) -ljsoncpp
libprivilege_la_include_HEADERS = cap.h 
libprivilege_la_LIBADD = $(LIBCAP_LIBS)
libprivilege_la_includedir = ${includedir}
