# This module extracts the usernames, websites for Chrome and organizes it in the Tree Viewer Window


# Please note this a non-exhaustive extraction of data, it is recommended to
# manually inspect the database for more forensic artifacts and use this as an indicator.
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
# Chrome Saved passwords identifier - tvdm
#

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



# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class ChromePWIngestModuleFactory(IngestModuleFactoryAdapter):

    moduleName = "Chrome Saved Passwords Identifier - tvdm"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Identifies Chrome Password databases and extracts information which could be used as indications. The saved passwords can demonstrate knowledge. Note: They will not be decrypted."

    def getModuleVersionNumber(self):
        return "1.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ChromePWIngestModule()



class ChromePWIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(ChromePWIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self):
        self.context = None


    def startUp(self, context):
        self.context = context
       
        pass
        
        
        
    
    def process(self, dataSource, progressBar):

        test=IngestServices.getInstance()
        msgcounter = 0
        progressBar.switchToIndeterminate()
        ccase = Case.getCurrentCase().getSleuthkitCase()
        blackboard = Case.getCurrentCase().getServices().getBlackboard()
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "Login Data")
        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0

        for file in files:
            fileCount += 1
            progressBar.progress(fileCount)
            progressBar.progress("Chrome Password Analyzer")
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK
            self.log(Level.INFO, "++++++Processing file: " + file.getName())
            self.log(Level.INFO, "File count:" + str(fileCount))
            lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".db")
            ContentUtils.writeToFile(file, File(lclDbPath))
            binary_file = open(lclDbPath, "rb")
            data = binary_file.read(15)
            binary_file.close()
            papa = ""
            if str(data) == "SQLite format 3":
                papa = file.getParentPath()
                message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                "Chrome Saved passwords", file.getName() + " identified as non-encrypted SQLite database" , str(msgcounter ))
                IngestServices.getInstance().postMessage(message)
                msgcounter+=1
                
                try: 
                    Class.forName("org.sqlite.JDBC").newInstance()
                    dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
                except SQLException as e:
                    message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                        "Chrome Saved passwords","Cannot open " + file.getName()+ " as SQLite", str(msgcounter))
                    IngestServices.getInstance().postMessage(message)
                    msgcounter+=1
                    return IngestModule.ProcessResult.ERROR
                
                try:
                    stmt = dbConn.createStatement()
                    
                    try: 
                        resultSet  = stmt.executeQuery("select origin_url, username_value,  datetime(date_created / 1000000 + (strftime('%s', '1601-01-01')), 'unixepoch') 'Creation date', CASE blacklisted_by_user WHEN 0 THEN 'remembered' ELSE 'not remembered' END 'Offered and ...' , times_used 'Times used' from logins;")
                        ccase = Case.getCurrentCase().getSleuthkitCase()
                        artifact_name = "TSK_CHRPW"
                        try:
                                #Try adding the Articaft Type
                                
                                artifact_desc = "Chrome Saved Passwords Identifier - TODO: ACCOUNT"
                                artID_chrpw = ccase.addArtifactType( artifact_name, artifact_desc)
                                
                        except:
                            self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")
                            artID_chrpw = ccase.getArtifactTypeID(artifact_name)
                            artID_chrpw_evt = ccase.getArtifactType(artifact_name)
                        try:
                            
                            attribute_name = "TSK_CHRPW_URL"
                            attribute_name2 = "TSK_CHRPW_USERNAME"
                            attribute_name3 = "TSK_CHRPW_DATE"
                            attribute_name4 = "TSK_CHRPW_REMEMBER"
                            attribute_name5 = "TSK_CHRPW_TIMES"
                            attID_ex1 = ccase.addArtifactAttributeType(attribute_name, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "URL")
                            attID_ex2 = ccase.addArtifactAttributeType(attribute_name2, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Username")
                            attID_ex3 = ccase.addArtifactAttributeType(attribute_name3, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Date")
                            attID_ex4 = ccase.addArtifactAttributeType(attribute_name4, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Offered and ...")
                            attID_ex5 = ccase.addArtifactAttributeType(attribute_name5, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "No of Times Used")
                        except:
                            pass
                        while resultSet.next():
                            if self.context.isJobCancelled():
                                message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                                    "Chrome Saved passwords", "ID : Canceled", str(msgcounter))
                                IngestServices.getInstance().postMessage(message)
                                msgcounter+=1
                                return IngestModule.ProcessResult.OK
                            art = file.newArtifact(artID_chrpw)
                            url = resultSet.getString("origin_url")
                            username = resultSet.getString("username_value")
                            date = resultSet.getString("Creation Date")
                            memory = resultSet.getString("Offered and ...")
                            times = resultSet.getString("Times used")
                            
                            #url 
                            attID_ex1 = ccase.getAttributeType("TSK_CHRPW_URL")
                            art.addAttribute(BlackboardAttribute(attID_ex1, ChromePWIngestModuleFactory.moduleName, url))
                            #username
                            attID_ex1 = ccase.getAttributeType("TSK_CHRPW_USERNAME")
                            art.addAttribute(BlackboardAttribute(attID_ex1, ChromePWIngestModuleFactory.moduleName, username))
                            #date
                            attID_ex1 = ccase.getAttributeType("TSK_CHRPW_DATE")
                            art.addAttribute(BlackboardAttribute(attID_ex1, ChromePWIngestModuleFactory.moduleName, date))
                            #memory
                            attID_ex1 = ccase.getAttributeType("TSK_CHRPW_REMEMBER")
                            art.addAttribute(BlackboardAttribute(attID_ex1, ChromePWIngestModuleFactory.moduleName, memory))
                            attID_ex1 = ccase.getAttributeType("TSK_CHRPW_TIMES")
                            art.addAttribute(BlackboardAttribute(attID_ex1, ChromePWIngestModuleFactory.moduleName, times))
                            artID_chrpw = ccase.getArtifactTypeID(artifact_name)
                            artID_chrpw_evt = ccase.getArtifactType(artifact_name)
                            IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(ChromePWIngestModuleFactory.moduleName, artID_chrpw_evt, None))
                        else:
                            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                                    "Chrome Saved passwords","No accounts found in" + file.getName(), str(msgcounter))
                            IngestServices.getInstance().postMessage(message)
                            msgcounter+=1
                    except SQLException as e:
                        self.log(Level.INFO, "SQL Error: " + e.getMessage() )
                except SQLException as e:
                            self.log(Level.INFO, "Error querying database " + file.getName() + " (" + e.getMessage() + ")")
                # Clean up
                stmt.close()
                dbConn.close()
                os.remove(lclDbPath)
                
            else:
                message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                    "Chrome Saved passwords","Not a SQLite Database - Missing magic number" , str(msgcounter ))
                IngestServices.getInstance().postMessage(message)
                msgcounter+=1
                return IngestModule.ProcessResult.ERROR
                
            
            
        # After all databases, post a message to the ingest messages in box.
        if numFiles==0:
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Chrome Saved passwords", "Nothing to analyze ", str(msgcounter))
            IngestServices.getInstance().postMessage(message)
            msgcounter+=1
        else:
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Chrome Saved passwords", "Analyzed %d files" % fileCount, str(msgcounter))
            IngestServices.getInstance().postMessage(message)
            msgcounter+=1
        return IngestModule.ProcessResult.OK