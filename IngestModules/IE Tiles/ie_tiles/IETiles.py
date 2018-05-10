# This module quickly extracts some data from identified Internet Explorer Tiles
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

def CalculateTime(arg1, arg2):
    microseconds = 0
    seconds = 0
    days = 0
    #Already Big Endian no need to swap bytes
    L = str(arg1).split('x')
    H =str(arg2).split('x')
        #print "LoValue: " + L[1] + " " + str( int(L[1], 16))
    #print "HiValue: " + H[1]  + " " + str(int(H[1], 16))
    both = H[1] + L[1]
    nano = int(both, 16)
    (s, rest) = divmod(nano - 116444736000000000  , 10000000)
    temp = datetime.utcfromtimestamp(s)
    return str(temp)
            
            
class IETilesIngestModuleFactory(IngestModuleFactoryAdapter):

    moduleName = "Tom IE Tiles Analyzer"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Tom IE Tiles Analyzer"

    def getModuleVersionNumber(self):
        return "1.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return IETilesIngestModule()



class IETilesIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(IETilesIngestModuleFactory.moduleName)

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
        #Current case
        ccase = Case.getCurrentCase().getSleuthkitCase()
        blackboard = Case.getCurrentCase().getServices().getBlackboard()
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "msapplication.xml")
        numFiles = len(files)
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,"IE Tiles Analyzer","About to analyze " + str(numFiles) + " files")
        PostBoard.postMessage(message)
        progressBar.switchToDeterminate(numFiles)
        
        
        try:
        #Try adding the Articaft Type
            artifact_name = "TSK_IETILES"
            artifact_desc = "IE Tiles Analyzer"
            
            artID_tiles = ccase.addArtifactType(artifact_name, artifact_desc)
            artID_tiles_evt = ccase.getArtifactType(artifact_name)
            attribute_name = "TSK_TILES_SITE"
            attribute_name2 = "TSK_TILES_DATE"
            attribute_name3 = "TSK_TILES_ACCESSDATE"
            attID_ex1 = ccase.addArtifactAttributeType(attribute_name, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Site")
            attID_ex2 = ccase.addArtifactAttributeType(attribute_name2, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Date")
            attID_ex3 = ccase.addArtifactAttributeType(attribute_name3, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Access Date")
        except:
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                "IE Tiles Analyzer","Already created?")
            PostBoard.postMessage(message)

        fileCount = 0
        for file in files:
            fileCount += 1
            progressBar.progress(fileCount)
            progressBar.progress("IE Tiles Analyzer")
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK
            self.log(Level.INFO, "++++++Processing file: " + file.getName())
            self.log(Level.INFO, "File count:" + str(fileCount))
            lclXMLPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".xml")
            ContentUtils.writeToFile(file, File(lclXMLPath))
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                "IE Tiles Analyzer",lclXMLPath)
            #PostBoard.postMessage(message)
            try:
                tree = ET.ElementTree(file=lclXMLPath)
                root = tree.getroot()
                for config in root.iter('site'):
                    site = config.attrib.get('src')
                    message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                        "IE Tiles Analyzer",site)
                    PostBoard.postMessage(message)
                for dates in root.iter('accdate'):
                    accessD = dates.text.split(",")
                    AloValue = accessD[0]
                    AhiValue = accessD[1]
                    accessdate = CalculateTime(AloValue, AhiValue)
                    
                for dates in root.iter('date'):
                    createD = dates.text.split(",")
                    CloValue = createD[0]
                    ChiValue  = createD[1]
                    normaldate = CalculateTime(CloValue, ChiValue)
                   
                if len(site) > 0:
                    artifact_name = "TSK_IETILES"
                    artifact_desc = "IE Tiles Analyzer"
                    artID_tiles_evt = ccase.getArtifactType(artifact_name)
                    artID_tiles = ccase.getArtifactTypeID(artifact_name)
                    art = file.newArtifact(artID_tiles)
                    attID_ex1 = ccase.getAttributeType("TSK_TILES_SITE")
                    art.addAttribute(BlackboardAttribute(attID_ex1, IETilesIngestModuleFactory.moduleName, site))
                    attID_ex1 = ccase.getAttributeType("TSK_TILES_DATE")
                    art.addAttribute(BlackboardAttribute(attID_ex1, IETilesIngestModuleFactory.moduleName, normaldate))
                    attID_ex1 = ccase.getAttributeType("TSK_TILES_ACCESSDATE")
                    art.addAttribute(BlackboardAttribute(attID_ex1, IETilesIngestModuleFactory.moduleName, accessdate))
                    PostBoard.fireModuleDataEvent(ModuleDataEvent(IETilesIngestModuleFactory.moduleName, \
                        artID_tiles_evt, None))
                else:
                    message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                        "IE Tiles Analyzer", "No sites found: " + lclXMLPath)
                    PostBoard.postMessage(message)
            
            except:
                message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                    "IE Tiles Analyzer","SOMETHING WENT WRONG")
                PostBoard.postMessage(message)
            # Clean up
            os.remove(lclXMLPath)
            

        # After all XML files, post a message to the ingest messages in box.
        if numFiles==0:
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "IE Tiles Analyzer", "Nothing to analyze ")
            PostBoard.postMessage(message)
        else:
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "IE Tiles Analyzer", "Analyzed %d files" % fileCount)
            PostBoard.postMessage(message)
        return IngestModule.ProcessResult.OK