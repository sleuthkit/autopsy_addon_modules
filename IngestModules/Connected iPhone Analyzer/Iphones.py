# Description:
# This module quickly extracts some data from identified Iphone Backup Plist
# This provides an indicator of possible connected iPhone/iPad/iPod devices.
# Please note this a non-exhaustive extraction of data, it is recommended to
# manually inspect the files for more forensic artifacts and use this as an indicator
#
# Contact: Tom Van der Mussele [tomvandermussele <at> gmail [dot] com]
#
# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
# 
#
# Looks for files of a given name, verifies the validity of the file, reads elements out of it
# and makes artifacts

import jarray
import inspect
import os
from java.lang import Class
from java.lang import System
from java.sql  import DriverManager, SQLException
from java.util.logging import Level
from java.io import File
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
#from org.sleuthkit.databases import TskDBBlackboard
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.casemodule.services import Blackboard
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, tzinfo
import time
import calendar


# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.

def Strip (arg1):
    temp = arg1.strip()
    temp2 = temp[8:]
    temp3 = temp2[:-9]
    return temp3
            
            
class IphoneIngestModuleFactory(IngestModuleFactoryAdapter):

    moduleName = "Connected iPhone Analyzer"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Identifies artifacts of possible connected iPhone/iPad/iPod devices."

    def getModuleVersionNumber(self):
        return "1.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return IphoneIngestModule()



class IphoneIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(IphoneIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self):
        self.context = None


    def startUp(self, context):
        self.context = context
       
        pass

    
    def process(self, dataSource, progressBar):

        PostBoard=IngestServices.getInstance()
        progressBar.switchToIndeterminate()
        ccase = Case.getCurrentCase().getSleuthkitCase()
        blackboard = Case.getCurrentCase().getServices().getBlackboard()
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "Info.plist")
        numFiles = len(files)
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,"Connected iPhone Analyzer","About to analyze " + str(numFiles) + " files")
        PostBoard.postMessage(message)
        progressBar.switchToDeterminate(numFiles)
        
        
        try:
            artifact_name = "TSK_IPHONE"
            artifact_desc = "Connected iPhone Analyzer"
            
            artID_iphone = ccase.addArtifactType(artifact_name, artifact_desc)
            artID_iphone_evt = ccase.getArtifactType(artifact_name)
            attribute_name = "TSK_IPHONE_DEVICENAME"
            attribute_name2 = "TSK_IPHONE_PRODUCTTYPE"
            attribute_name3 = "TSK_IPHONE_BACKUPDATE"
            attribute_name4 = "TSK_IPHONE_PHONENUMBER"
            attribute_name5 = "TSK_IPHONE_SERIALNUMBER"
            attribute_name6 = "TSK_IPHONE_IMEI"
            attribute_name7 = "TSK_IPHONE_ICCID"
            attribute_name8 = "TSK_IPHONE_BUILD"
            attID_ex1 = ccase.addArtifactAttributeType(attribute_name, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Name")
            attID_ex2 = ccase.addArtifactAttributeType(attribute_name2, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Type")
            attID_ex3 = ccase.addArtifactAttributeType(attribute_name3, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "BackupDate")
            attID_ex4 = ccase.addArtifactAttributeType(attribute_name4, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Phone Number")
            attID_ex5 = ccase.addArtifactAttributeType(attribute_name5, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Serial")
            attID_ex6 = ccase.addArtifactAttributeType(attribute_name6, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "IMEI")
            attID_ex7 = ccase.addArtifactAttributeType(attribute_name7, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "ICCID")
            attID_ex8 = ccase.addArtifactAttributeType(attribute_name8, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "BUILD")
        except:
            a = 1

        fileCount = 0
        for file in files:
            fileCount += 1
            progressBar.progress(fileCount)
            progressBar.progress("Connected iPhone Analyzer")
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK
            self.log(Level.INFO, "++++++Processing file: " + file.getName())
            
            lclPlistPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".plist")
            ContentUtils.writeToFile(file, File(lclPlistPath))
            try:
                plist_file = open(lclPlistPath, 'r')
                lines = plist_file.readlines()
                
                BUILDVERSION = ""
                devicename = ""
                GUID = ""
                ICCID = ""
                IMEI=""
                LASTBACKUP = ""
                PHONENUMBER = ""
                PRODUCTTYPE = ""
                SERIALNUMBER = ""
                if "<!DOCTYPE plist PUBLIC " in lines[1] and "Apple//DTD PLIST 1.0//EN" in lines[1] and "http://www.apple.com/DTDs/PropertyList" in lines[1]:
                    IPHONE_PLIST = 0
                    counter = 0
                    for i in lines:
                        if "key>Build Version</key>" in lines[counter]:
                            IPHONE_PLIST = 1
                        else:
                            a = 1 + 1
                        counter += 1
                        
                    
                    if IPHONE_PLIST == 1:
                        j = 0
                        while j!=counter:
                            
                            if "Build Version" in lines[j]:
                                BUILDVERSION =  Strip(lines[j + 1])
                                print "BUILD:" + BUILDVERSION
                                j += 1
                            if  "<key>Device Name</key>" in lines[j]:
                                devicename = Strip(lines[j + 1])
                                j += 1
                            if  "<key>GUID</key>" in lines[j]:
                                GUID = Strip(lines[j + 1])
                                j += 1
                            if  "<key>ICCID</key>" in lines[j]:
                                ICCID = Strip(lines[j + 1])
                                j += 1
                            if  "<key>IMEI</key>" in lines[j]:
                                IMEI = Strip(lines[j + 1])
                                j += 1
                            if  "<key>Last Backup Date</key>" in lines[j]:
                                LASTBACKUP = Strip(lines[j + 1])
                                j += 1
                            if  "<key>Phone Number</key>" in lines[j]:
                                PHONENUMBER = Strip(lines[j + 1])
                                j += 1    
                            if  "<key>Product Type</key>" in lines[j]:
                                PRODUCTTYPE = Strip(lines[j + 1])
                                j += 1    
                            if  "ey>Serial Number</key>" in lines[j]:
                                SERIALNUMBER = Strip(lines[j + 1])
                                j += 1    
                            j += 1

                        artifact_name = "TSK_IPHONE"
                        artifact_desc = "Connected iPhone Analyzer"
                        artID_iphone_evt = ccase.getArtifactType(artifact_name)
                        artID_iphone = ccase.getArtifactTypeID(artifact_name)
                        art = file.newArtifact(artID_iphone)
                        attID_ex1 = ccase.getAttributeType("TSK_IPHONE_DEVICENAME")
                        art.addAttribute(BlackboardAttribute(attID_ex1, IphoneIngestModuleFactory.moduleName, devicename))
                        attID_ex1 = ccase.getAttributeType("TSK_IPHONE_PRODUCTTYPE")
                        art.addAttribute(BlackboardAttribute(attID_ex1, IphoneIngestModuleFactory.moduleName, PRODUCTTYPE))
                        attID_ex1 = ccase.getAttributeType("TSK_IPHONE_BACKUPDATE")
                        art.addAttribute(BlackboardAttribute(attID_ex1, IphoneIngestModuleFactory.moduleName, LASTBACKUP))
                        attID_ex1 = ccase.getAttributeType("TSK_IPHONE_PHONENUMBER")
                        art.addAttribute(BlackboardAttribute(attID_ex1, IphoneIngestModuleFactory.moduleName, PHONENUMBER))
                        attID_ex1 = ccase.getAttributeType("TSK_IPHONE_SERIALNUMBER")
                        art.addAttribute(BlackboardAttribute(attID_ex1, IphoneIngestModuleFactory.moduleName, SERIALNUMBER))
                        attID_ex1 = ccase.getAttributeType("TSK_IPHONE_IMEI")
                        art.addAttribute(BlackboardAttribute(attID_ex1, IphoneIngestModuleFactory.moduleName, IMEI))
                        attID_ex1 = ccase.getAttributeType("TSK_IPHONE_ICCID")
                        art.addAttribute(BlackboardAttribute(attID_ex1, IphoneIngestModuleFactory.moduleName, ICCID))
                        attID_ex1 = ccase.getAttributeType("TSK_IPHONE_BUILD")
                        art.addAttribute(BlackboardAttribute(attID_ex1, IphoneIngestModuleFactory.moduleName, BUILD))
                        PostBoard.fireModuleDataEvent(ModuleDataEvent(IphoneIngestModuleFactory.moduleName, \
                            artID_iphone_evt, None))
                        IPHONE_PLIST = 0
                        plist_file.close()
                    else:

                        plist_file.close()
                else:

                    plist_file.close()
            except:

                plist_file.close()

            os.remove(lclPlistPath)
            

        # After all Plist files, post a message to the ingest messages in box.
        if numFiles==0:
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Connected iPhone Analyzer", "Nothing to analyze ")
            PostBoard.postMessage(message)
        else:
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Connected iPhone Analyzer", "Analyzed %d files" % fileCount)
            PostBoard.postMessage(message)
        return IngestModule.ProcessResult.OK