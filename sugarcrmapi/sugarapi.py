#!/usr/bin/python
#
#
# Software License Agreement
# Copyright (c) 2011-2013, XMOS Ltd, All rights reserved.
#
# Additional copyright holders (each contributor holds copyright
# over contribution as described in the git commit logs for the repository):
#
# The copyright holders hereby grant to any person obtaining a copy of this software (the "Software") and/or its associated
# documentation files (the Documentation), the perpetual, irrevocable (except in the case of breach of this license) no-cost,
# royalty free, sublicensable rights to use, copy, modify, merge, publish, display, publicly perform, distribute, and/or
# sell copies of the Software and the Documentation, together or separately, and to permit persons to whom the Software and/or
# Documentation is furnished to do so, subject to the following conditions:
#
# . Redistributions of the Software in source code must retain the above copyright notice, this list of conditions and the
# following disclaimers.
#
# . Redistributions of the Software in binary form must reproduce the above copyright notice, this list of conditions and
# the following disclaimers in the documentation and/or other materials provided with the distribution.
#
# . Redistributions of the Documentation must retain the above copyright notice, this list of conditions and the following
# disclaimers.
#
# Neither the name of XMOS, nor the names of its contributors may be used to endorse or promote products derived from this
# Software or the Documentation without specific prior written permission of the copyright holder.
#
# THE SOFTWARE AND DOCUMENTATION ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
# LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# CONTRIBUTORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR DOCUMENTATION OR THE USE OF OR OTHER
# DEALINGS WITH THE SOFTWARE OR DOCUMENTATION.
#
#********************************************************************
#
#

#
#
#
# SugarCRM API help and list of API entry points
# <Sugar_Instance>/rest/v10/help
#
# SugarCRM API examples
# http://support.sugarcrm.com/02_Documentation/04_Sugar_Developer/Sugar_Developer_Guide_7.1/70_API/Web_Services/20_Examples/v10/
#
#********************************************************************

import sys
import json
import requests
import subprocess
import datetime 
import time
import os
from os.path import expanduser
import base64
from urlparse import urlsplit
import re

class SugarAPI:

    def __init__(self, Host='', base_part_url='/rest/v10', username='', password='', platform='', AuthFile='', ForceLogin=False, NumSequenceMax=10):
        self.oauth2_token=""
        self.login_url = ""
        self.base_url=""
        self.username=username
        self.password=password
        self.platform=platform
        self.oauth2_token_arguments = {}
        self.client_id="sugar"
        self.client_secret=""
        self.auth_url="/oauth2/token"
        self.Create={}
        self.ReadByID={}
        self.UpdateByID={}
        self.DeleteByID={}
        self.AuthFilePrefix = ".sugarcrm-auth"
        #self.AuthFileCode = base64.b64encode(os.urandom(10))
        self.AuthFileCode = "base"
        self.AuthFileDir = "/tmp"
        self.AuthFileDir = expanduser("~")

        self.Host = Host
        self.base_part_url = base_part_url
        self.AuthFile=AuthFile
        self.ForceLogin=ForceLogin
        self.NumSequenceMax=NumSequenceMax
        self.base_url = self.Host + self.base_part_url

        self.SugarDetails = {"host": Host,
            "auth_token": '',
            "num_sequence": 1,
            "num_sequence_max": NumSequenceMax,
            "platform": platform,
        }

    def call (self, url, oauthtoken='', type='GET', arguments={}, encodeData=True, returnHeaders=False):
        data={}
        params={}
        headers={}
        argumentsp = arguments.copy()

        if type.upper() == 'GET':
            if argumentsp:
                print "Info: Setting PHP arguments"
                #json_call_arguments=json.dumps(arguments)
                ##print json_call_arguments
                #Prefix="/home/robd/CRM/crm/Nehanet/bin/sugarcrmapi"
                #argp=Prefix + "/httpbq.php '" + json_call_arguments + "'"
                ##print argp
                #p=subprocess.Popen(argp, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                #for line in p.stdout.readlines():
                #    gparams=line,
                #retval=p.wait()
                #params=''.join(gparams)
                #if retval != 0:
                #    print "Error: Problem converting arguments to PHP JSON string"
                #    sys.exit(1)

                json_call_arguments=json.dumps(argumentsp)
                #print json_call_arguments
                FileID=base64.b64encode(os.urandom(10))
                FileID=os.urandom(10)
                FileID=str(os.getpid())
                Prefix="/tmp/"
                argp=Prefix + "httpbq-" + FileID + ".php"

                LinePHP=[]
                LinePHP.append("#!/usr/bin/php")
                LinePHP.append("<?php")
                LinePHP.append("$jsonargument='%s';" %(json_call_arguments))
                LinePHP.append("$arguments=json_decode($jsonargument);")
                LinePHP.append("printf('%s', http_build_query($arguments));")
                LinePHP.append("?>")

                try:
                    file = open(argp, "w")
                except:
                    print "Error: Cannot write file %s" %(argp)
                for entry in LinePHP:
                    #print "Info: entry %s" %(entry)
                    file.write(entry + "\n")
                file.close()

                #print argp
                p=subprocess.Popen("/usr/bin/php " + argp, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


                for line in p.stdout.readlines():
                    gparams=line,
                #print gparams
                retval=p.wait()
                params=''.join(gparams)
                os.remove(argp)
                if retval != 0:
                    print "Error: Problem converting arguments to PHP JSON string"
                    sys.exit(1)


        header_verify=False
        header_allow_redirects=False

        if oauthtoken:
            tokena = 'oauth-token: ' + oauthtoken
            token=tokena.encode('ascii', 'ignore')
            headers={'oauth-token': oauthtoken}

        if argumentsp and type != 'GET':
            if encodeData:
                argumentsp = json.dumps(argumentsp)
            data=argumentsp

        MaxLoop = 10
        NLoop = 1
        SleepSet = 2
        Loop = True
        while Loop:
            try:
                print "Info: Trying to connect to server (%s/%s)" %(NLoop, MaxLoop)
                print "url %s" %(url)
                print "Type %s" %(type)
                print "params %s" %(params)
                print "data %s" %(data)
                r=requests.request(type.upper(), url, params=params, data=data, verify=header_verify, headers=headers)

                print "Info: Successfully connected to server"

                #print "r %s" %(r)
                #print "URL sent %s" %(r.url)
                #print "response %s" %(r.content)
                #print "status code %S" %(r.status_code)
                #

                response = json.loads(r.content)
                Loop = False
            except:
                try:
                    response = r.content
                    rurl = r.url
                    rresp = r
                except:
                    response = "No Response"
                    rurl = ""
                    rresp = ""
#
                print "Error: Failure in URL request (%s/%s)" %(NLoop, MaxLoop)
                print "Info: Response is %s" %(response)
                print "Info: url %s" %(url)
                print "Info: Type %s" %(type)
                print "Info: params %s" %(params)
                print "Info: data %s" %(data)
                print "Info: Returned request %s" %(rurl)
                print "Info: Returned %s" %(rresp)
                try:
                    print "Info: Returned text %s" %(r.text)
                    e = ""
                    try:
                        r.raise_for_status()
                    except requests.exceptions.HTTPError as e:
                        print "Info: Returned error %s" %(e)

#
                    StatusCode = r.status_code
                    #p=re.compile("500 Server Error")
                    #print "Info: Error %s" %(str(e))
                    #if p.search(str(e)):
                    if StatusCode == 500:
                        print "Info: Force login"
                        self.login(ForceLogin=True)
                    elif StatusCode == 401:
                        print "Info: Getting refresh token"
                        login(GetRefresh=True)
#
                except:
                    print "Error: No return from URL request"
#
                if NLoop < MaxLoop:
                    Loop = True
                    SleepTime = NLoop * SleepSet
                    print "Info: Trying again, wait %s seconds" %(SleepTime)
                    time.sleep(SleepTime)
                else:
                    print "Info: Too many tries"
                    Now = datetime.datetime.now()
                    print "Info: Date and time now %s" %(Now)
#
                    Loop = False
                    raise Exception("Too many tries connecting to URL  Response from server %s" %(response))
#
            NLoop += 1


        return response
#
# Actions wrapper for Sugar including logging in again if necessary
#
    def SugarAction(self, DoWhatList):
#
#DoWhatList={"action": "Update_Module_By_ID",
#       "parameters": {
#            "module": "Leads",
#            "id": ID,
#            "record": module_record,
#       }
#}
#DoWhatList={"action": "Read_Module_By_Filter",
#       "parameters": {
#            "module": "Leads",
#            "filter": Args,
#            "type": "POST",
#       }
#}
#DoWhatList={"action": "Count_Module_By_Filter",
#       "parameters": {
#            "module": "Leads",
#            "filter": Args,
#       }
#}
#DoWhatList={"action": "Create_Module",
#       "parameters": {
#            "module": "Leads",
#            "record": module_record,
#       }
#}
#DoWhatList={"action": "RunCustomAPI",
#       "parameters": {
#            "url": URL,
#            "type": TYPE,
#            "record": module_details,
#       }
#}
#DoWhatList={"action": "Read_Module_Link",
#       "parameters": {
#            "module": "Accounts",
#            "id": ID,
#            "link": "contacts",
#            "filter": Args,
#       }
#}
#DoWhatList={"action": "Create_Module_Link",
#       "parameters": {
#            "module": "Accounts",
#            "id": ID,
#            "record": module_details,
#       }
#}
#DoWhatList={"action": "Delete_Module_By_ID",
#       "parameters": {
#            "module": "Accounts",
#            "id": ID,
#       }
#}
#DoWhatList={"action": "Delete_Module_Mass",
#       "parameters": {
#            "module": "Accounts",
#            "filter": Args,
#       }
#}
#DoWhatList={"action": "Update_Module_Mass",
#       "parameters": {
#            "module": "Accounts",
#            "record": module_details,
#       }
#}
#DoWhatList={"action": "Get_Metadata",
#       "parameters": {
#            "filter": module_filter,
#       }
#}
#
        Host = self.SugarDetails["host"]
        oauth2_token_response = self.SugarDetails["auth_token"]
#
        self.SugarDetails["num_sequence"] += 1
        if not oauth2_token_response:
            print "Info: No oauth2 token, logging into server"
            self.SugarDetails["num_sequence"] = self.SugarDetails["num_sequence_max"] + 1

        #print "Platform %s" %(self.SugarDetails["num_sequence"])
        #print "Platform %s" %(self.SugarDetails["num_sequence_max"])
        if self.SugarDetails["num_sequence"] > self.SugarDetails["num_sequence_max"]:
            print "Info: Reset Platform"
            self.SugarDetails["num_sequence"] = 1
            self.login()
#
        Platform = self.oauth2_token_arguments["platform"]
        username = self.oauth2_token_arguments["username"]
        password = self.oauth2_token_arguments["password"]
#
        DoWhat = DoWhatList["action"]
#
        AU = {}
        MAXTRY = 3
        TRY = 1
        SleepSet = 1
        while TRY <= MAXTRY:
#
            if DoWhat == "Update_Module_By_ID":
                Module = DoWhatList["parameters"]["module"]
                ID = DoWhatList["parameters"]["id"]
                Record = DoWhatList["parameters"]["record"]
                AU=self.Update_Module_By_ID(Module, ID, Record)
#
            elif DoWhat == "Read_Module_By_Filter":
                Module = DoWhatList["parameters"]["module"]
                filter = DoWhatList["parameters"]["filter"]
                if "type" in DoWhatList["parameters"]:
                    Type = DoWhatList["parameters"]["type"]
                else:
                    Type = "POST"
                AU=self.Read_Module_By_Filter(Module, filter, Type)
#
            elif DoWhat == "Count_Module_By_Filter":
                Module = DoWhatList["parameters"]["module"]
                filter = DoWhatList["parameters"]["filter"]
                AU=self.Count_Module_By_Filter(Module, filter)
#
            elif DoWhat == "Create_Module":
                Module = DoWhatList["parameters"]["module"]
                Record = DoWhatList["parameters"]["record"]
                AU=self.Create_Module(Module, Record)
#
            elif DoWhat == "RunCustomAPI":
                URL = DoWhatList["parameters"]["url"]
                TYPE = DoWhatList["parameters"]["type"]
                module_details = DoWhatList["parameters"]["record"]
                AU = self.RunCustomAPI(URL, TYPE, module_details)
#
            elif DoWhat == "Read_Module_Link":
                Module = DoWhatList["parameters"]["module"]
                ID = DoWhatList["parameters"]["id"]
                LinkName = DoWhatList["parameters"]["link"]
                if "filter" in DoWhatList["parameters"]:
                    filter = DoWhatList["parameters"]["filter"]
                else:
                    filter = {}
                AU = self.Read_Module_Link(Module, ID, LinkName, filter)
#
            elif DoWhat == "Create_Module_Link":
                Module = DoWhatList["parameters"]["module"]
                Record = DoWhatList["parameters"]["record"]
                ID = DoWhatList["parameters"]["id"]
                AU = self.Create_Module_Link(Module, Record, ID)
#
            elif DoWhat == "Delete_Module_By_ID":
                Module = DoWhatList["parameters"]["module"]
                ID = DoWhatList["parameters"]["id"]
                AU = self.Delete_Module_By_ID(Module, ID)
#
            elif DoWhat == "Delete_Module_Mass":
                Module = DoWhatList["parameters"]["module"]
                if "filter" in DoWhatList["parameters"]:
                    filter = DoWhatList["parameters"]["filter"]
                else:
                    filter = {}
                AU = self.Delete_Module_Mass(Module, filter)
#
            elif DoWhat == "Update_Module_Mass":
                Module = DoWhatList["parameters"]["module"]
                Record = DoWhatList["parameters"]["record"]
                AU = self.Update_Module_Mass(Module, Record)
#
            elif DoWhat == "Get_Metadata":
                filter = DoWhatList["parameters"]["filter"]
                AU = self.Get_Metadata(filter)
#
            #print json.dumps(AU, sort_keys=True, indent=4, separators=(',', ': '))
            if "error_message" in AU:
                print "Error: Did not process record for %s" %(DoWhat)
                print "Error: Message is |%s|" %(AU["error_message"])
                if AU["error_message"] == "The access token provided is invalid." or AU["error_message"] == "The access token provided has expired.":
                    print "Error: Access token invalid, trying to log in again"
                    self.SugarDetails["num_sequence"]=1
                    self.login(ForceLogin=True)

                    TRY += 1
                    SleepTime = TRY * SleepSet
                    time.sleep(SleepTime)
                else:
                    TRY = MAXTRY + 1
            else:
                print "Info: Sugar Action successful for %s" %(DoWhat)
                TRY = MAXTRY + 1
#
        return AU
#
# Set the authorisation file
#
    def setAuthFile(self):
        epoch_time = int(time.time())
        ExpiresTimeEpoch = epoch_time + self.oauth2_token["expires_in"]
        ExpiresTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ExpiresTimeEpoch))

        Status=True
        try:
            file = open(self.AuthFile, "w")
        except:
            print "Error: Cannot write file %s" %(self.AuthFile)
            Status=False

        if Status:
            file.write("expires_time:" + ExpiresTime + "\n")
            for entry in self.oauth2_token:
                #print "Info: entry %s" %(entry)
                file.write(str(entry) + ":" + str(self.oauth2_token[entry]) + "\n")
            file.close()
            print "Info: Finished writing Auth file"

        return Status

    def getAuthFile(self):
        line=[]
        try:
            file = open(self.AuthFile, 'r')
            line = file.readlines()
            file.close()
            ExpiresTime = line[0].rstrip()
        except:
            ExpiresTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
            line.append("expires_time:" + ExpiresTime)

        data=[]
        var={}
        for entry in line:
            data=entry.rstrip()
            dataa = data.partition(":")
            var[dataa[0]] = dataa[2]

        return var

    def login(self, Host='', base_part_url='/rest/v10', username='', password='', platform='', AuthFile='', ForceLogin=False, NumSequenceMax=0, GetRefresh=False):
#
            
        if Host:
            self.Host = Host

        if base_part_url:
            self.base_part_url = base_part_url

        self.base_url = self.Host + self.base_part_url

        self.login_url = self.base_url + self.auth_url

        if username:
            self.username = username
            self.password = password

        if platform:
            self.platform = platform

        if NumSequenceMax:
            self.NumSequenceMax = NumSequenceMax
#
        self.oauth2_token_arguments = {
            "grant_type": "password",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "username": self.username,
            "password": self.password,
            "platform": self.platform,
        }
        print "Info: Platform %s" %(self.platform)
        print "Info: AuthFile %s" %(AuthFile)
        if not AuthFile:
            print "Info: Authfile not set"
            hostname = urlsplit(self.base_url).hostname
            self.AuthFile = self.AuthFileDir + "/" + self.AuthFilePrefix + "-" + self.username + "-" + hostname+ "-" + self.AuthFileCode
        else:
            print "Info: Custom Authfile"
            self.AuthFile=AuthFile
        print "Info: Authfile %s" %(self.AuthFile)

        #print json.dumps(self.oauth2_token_arguments, sort_keys=True, indent=4, separators=(',', ': '))
        print "Info: Login url %s" %(self.login_url)

        oauth2_token_cache = self.getAuthFile()
        if "expires_time" in oauth2_token_cache:
            ExpiresTime = oauth2_token_cache["expires_time"]
            print "Expires time %s" %(ExpiresTime)
            A=time.strptime(ExpiresTime, '%Y-%m-%d %H:%M:%S')
            ExpiresTimeEpoch = time.mktime(time.strptime(ExpiresTime, '%Y-%m-%d %H:%M:%S'))
            print "Expires time Epoch %s" %(ExpiresTimeEpoch)

            NowTime = int(time.time())
            print "Now %s " %(NowTime)
            TimeDiff = ExpiresTimeEpoch - NowTime
            print "Time to Expires %s" %(TimeDiff)
        else:
            TimeDiff = 0

        Login=False
        #if TimeDiff < 300:
        #    Login=True
        #    if TimeDiff > 30:
        #        GetRefresh=True
        #    else:
        #        GetRefresh=False
        if not GetRefresh:
            if TimeDiff < 30:
                Login=True
                GetRefresh=True
            else:
                GetRefresh=False
                Login=False
        else:
            Login = True

        if ForceLogin:
            GetRefresh = False

        if GetRefresh:
            #print oauth2_token_cache
            print "Info: Refreshing authentication token"
            self.oauth2_token_arguments = {
                "refresh_token":oauth2_token_cache["refresh_token"],
                "grant_type":"refresh_token",
                "client_id":self.client_id,
                "client_secret":self.client_secret,
                "platform": self.platform,
                "username":self.username,
                "password":self.password,
            }
        else:
            print "Info: New or cached authentication token"
            self.oauth2_token_arguments = {
                "grant_type":"password",
                "client_id":self.client_id,
                "client_secret":self.client_secret,
                "username":self.username,
                "password":self.password,
                "platform": self.platform,
            }

        SugarCall = False
        if Login or ForceLogin:
            print "Info: Logging into SugarCRM"
            #print self.oauth2_token_arguments
            Try = 1
            TryMax = 3
            while Try <= TryMax:
                print "Info: Getting refresh token"
                self.oauth2_token=self.call(self.login_url, '', 'POST', self.oauth2_token_arguments)
                #print self.oauth2_token
                if "error" in self.oauth2_token:
                    print "Error: %s" %(self.oauth2_token["error_message"])
                    SugarCall = False
                    if self.oauth2_token["error_message"] == "Invalid refresh token":
                        self.oauth2_token_arguments = {
                            "grant_type":"password",
                            "client_id":self.client_id,
                            "client_secret":self.client_secret,
                            "username":self.username,
                            "password":self.password,
                            "platform": self.platform,
                        }
                        Try += 1
                        time.sleep(1)
                    else:
                        Try = TryMax + 1
                else:
                    print "Info: Logged into SugarCRM"
                    Try = TryMax + 1
                    self.setAuthFile()
                    SugarCall = False
        else:
            print "Info: Using cached token"
            self.oauth2_token={}
            for key in [ "access_token", "expires_in", "refresh_token", "token_type"]:
                #print "Info: key %s" %(key)
                if key in oauth2_token_cache:
                    self.oauth2_token[key]=oauth2_token_cache[key]
            #self.setAuthFile()
            #SugarCall = True
            SugarCall = False

        #print "oauth2_token"
        #print json.dumps(self.oauth2_token, sort_keys=True, indent=4, separators=(',', ': '))

        if SugarCall:
            print "Info: Logging into server to authenticate"
            self.oauth2_token=self.call(self.login_url, '', 'POST', self.oauth2_token_arguments)

        self.SugarDetails={"host": self.Host,
            "auth_token": self.oauth2_token,
            "platform": self.platform,
            "num_sequence": 1,
            "num_sequence_max": self.NumSequenceMax,
        }

        return
#
# Create
#
    def Create_Module(self, Module, module_details):
        return self.call(self.base_url + "/" + Module , self.oauth2_token['access_token'], "POST", module_details, True, False)

    def Create_Module_Link(self, Module, module_details, ID):
        return self.call(self.base_url + "/" + Module + "/" + ID + "/link", self.oauth2_token['access_token'], "POST", module_details, True, False)
#
# Read
#
    def Read_Module_List(self, Module, Args={}):
        return self.call(self.base_url + "/" + Module, self.oauth2_token['access_token'], 'GET', Args, True, False)

    def Read_Module_By_ID(self, Module, ID):
        return self.call(self.base_url + "/" + Module + "/" + ID, self.oauth2_token['access_token'], 'GET', {}, True, False)

    def Read_Module_By_Filter(self, Module, filter={}, Type="POST"):
        return self.call(self.base_url + "/" + Module + "/filter", self.oauth2_token['access_token'], Type, filter, True, False)

    def Read_Module_Link(self, Module, ID, LinkName, filter={} ):
        return self.call(self.base_url + "/" + Module + "/" + ID + "/link/" + LinkName, self.oauth2_token['access_token'], "GET", filter, True, False)
#
# Count
#
    def Count_Module_By_Filter(self, Module, filter={}):
        return self.call(self.base_url + "/" + Module + "/filter/count", self.oauth2_token['access_token'], "POST", filter, True, False)
#
# Update
#
    def Update_Module_By_ID(self, Module, ID, module_details):
        return self.call(self.base_url + "/" + Module + "/" + ID, self.oauth2_token['access_token'], "PUT", module_details, True, False)

    def Update_Module_Mass(self, Module, module_details):
        return self.call(self.base_url + "/" + Module + "/MassUpdate", self.oauth2_token['access_token'], "PUT", module_details, True, False)
#
# Run Custom API
#
    def RunCustomAPI(self, URL, TYPE, module_details):
       # print "Run Custom API"
       # print "URL %s" %(URL)
       # print "TYPE %s" %(TYPE)
        return self.call(self.base_url + "/" + URL, self.oauth2_token['access_token'], TYPE, module_details, True, False)
#
# Delete
#
    def Delete_Module_By_ID(self, Module, ID):
        return self.call(self.base_url + "/" + Module + "/" + ID, self.oauth2_token['access_token'], 'DELETE', {}, True, False)
    def Delete_Module_Mass(self, Module, Args={}):
        return self.call(self.base_url + "/" + Module + "/MassUpdate", self.oauth2_token['access_token'], 'DELETE', Args, True, False)
#
# Metadata
#
    def Get_Metadata(self, Args={}):
        return self.call(self.base_url + "/metadata", self.oauth2_token['access_token'], 'GET', Args, True, False)
#
