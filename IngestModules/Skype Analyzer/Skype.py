# This module extracts some data (chats, IP addresses, calls info,...) from identified Skype databases and organizes it in the Tree Viewer Window


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
# Skype Analyzer - tvdm
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
class SkypeDbIngestModuleFactory(IngestModuleFactoryAdapter):

    moduleName = "Skype Analyzer - tvdm"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Identifies Skype databases and extracts information which could be used as indications"

    def getModuleVersionNumber(self):
        return "1.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return SkypeDbIngestModule()



class SkypeDbIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(SkypeDbIngestModuleFactory.moduleName)

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
        files = fileManager.findFiles(dataSource, "main.db")
        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0

        for file in files:
            fileCount += 1
            progressBar.progress(fileCount)
            progressBar.progress("Skype Analyzer")
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK
            self.log(Level.INFO, "++++++Processing file: " + file.getName())
            self.log(Level.INFO, "File count:" + str(fileCount))
            lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".db")
            ContentUtils.writeToFile(file, File(lclDbPath))
            binary_file = open(lclDbPath, "rb")
            data = binary_file.read(15)
            binary_file.close()
            if str(data) == "SQLite format 3":
                message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                "Skype Analyzer", file.getName() + " identified as non-encrypted SQLite database" , str(msgcounter ))
                IngestServices.getInstance().postMessage(message)
                msgcounter+=1
                try: 
                    Class.forName("org.sqlite.JDBC").newInstance()
                    dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
                except SQLException as e:
                    message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                        "Skype Analyzer","Cannot open " + file.getName()+ " as SQLite", str(msgcounter))
                    IngestServices.getInstance().postMessage(message)
                    msgcounter+=1
                    #return IngestModule.ProcessResult.ERROR
                # Query the contacts table in the database and get all columns. 
                try:
                    stmt = dbConn.createStatement()
                    stmt2 = dbConn.createStatement()
                    stmt3 = dbConn.createStatement()
                    stmt4 = dbConn.createStatement()
                    stmt5 = dbConn.createStatement()
                    try: 
                        resultSet4  = stmt4.executeQuery("select skypename from accounts;")
                        resultSet5 = stmt5.executeQuery("select count(skypename) 'count' from accounts;")
                        skypename = resultSet4.getString("skypename")
                        no_of_accounts = resultSet5.getInt("count")
                        if no_of_accounts > 0:
                            ccase = Case.getCurrentCase().getSleuthkitCase()
                            SQL_String_1 = "Select chatname, author, datetime(timestamp, 'unixepoch') 'Time' ,body_xml 'Message'  from messages ORDER by Time asc;"
                            artifact_name = "TSK_MSG_" + skypename
                            artifact_desc = "Skype Analyzer Chats: " + skypename
                            try:
                                #Try adding the Articaft Type
                                artID_skype = ccase.addArtifactType(artifact_name, artifact_desc)
                            except:
                                self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")
                            artID_skype = ccase.getArtifactTypeID(artifact_name)
                            artID_skype_evt = ccase.getArtifactType(artifact_name)
                            #
                            #    Messages
                            #
                            #
                            resultSet3 = stmt3.executeQuery(SQL_String_1)
                            resultSet2 = stmt2.executeQuery("SELECT count(*) 'Count' from Messages;")
                            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                                "Skype Analyzer", skypename + " has " + str(resultSet2.getInt("Count")) + " messages", str(msgcounter))
                            IngestServices.getInstance().postMessage(message)
                            msgcounter+=1
                            if resultSet2.getInt("Count") > 0:
                            
                               
                                try:
                                    
                                    attribute_name = "TSK_SKYPE_MSG_AUTHOR"
                                    attribute_name2 = "TSK_SKYPE_MSG_TIME"
                                    attribute_name3 = "TSK_SKYPE_MSG_MESSAGE"
                                    attribute_name4 = "TSK_SKYPE_MSG_CHATNAME"
                                    attID_ex1 = ccase.addArtifactAttributeType(attribute_name2, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Time")
                                    attID_ex2 = ccase.addArtifactAttributeType(attribute_name, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Author")
                                    attID_ex3 = ccase.addArtifactAttributeType(attribute_name3, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Message")
                                    attID_ex4 = ccase.addArtifactAttributeType(attribute_name4, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Chatname")
                                except:
                                    pass
                                while resultSet3.next():
                                    if self.context.isJobCancelled():
                                        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                                            "Skype Analyzer", "ID : Cancelled", msgcounter)
                                            
                                        IngestServices.getInstance().postMessage(message)
                                        msgcounter+=1
                                        return IngestModule.ProcessResult.OK
                                    art = file.newArtifact(artID_skype)
                                    author = resultSet3.getString("author")
                                    time = resultSet3.getString("Time")
                                    msg = resultSet3.getString("Message")
                                    chatname = resultSet3.getString("chatname")
                                    #Chatname
                                    attID_ex1 = ccase.getAttributeType("TSK_SKYPE_MSG_CHATNAME")
                                    art.addAttribute(BlackboardAttribute(attID_ex1, SkypeDbIngestModuleFactory.moduleName, chatname))
                                    #Time
                                    attID_ex1 = ccase.getAttributeType("TSK_SKYPE_MSG_TIME")
                                    art.addAttribute(BlackboardAttribute(attID_ex1, SkypeDbIngestModuleFactory.moduleName, time))
                                    #Author
                                    attID_ex1 = ccase.getAttributeType("TSK_SKYPE_MSG_AUTHOR")
                                    art.addAttribute(BlackboardAttribute(attID_ex1, SkypeDbIngestModuleFactory.moduleName, author))
                                    #Message
                                    attID_ex1 = ccase.getAttributeType("TSK_SKYPE_MSG_MESSAGE")
                                    art.addAttribute(BlackboardAttribute(attID_ex1, SkypeDbIngestModuleFactory.moduleName, msg))
                                IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(SkypeDbIngestModuleFactory.moduleName, \
                                    artID_skype_evt, None))
                            else:
                                message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                                    "Skype Analyzer", skypename + " has no messages", str(msgcounter))
                                IngestServices.getInstance().postMessage(message)
                                msgcounter+=1
                            #
                            #    Calls
                            #
                            #
                            artifact_name2 = "TSK_CALL_" + skypename
                            artifact_desc2 = "Skype Analyzer Calls: " + skypename
                            try:
                                #Try adding the Articaft Type
                                artID_skype = ccase.addArtifactType( artifact_name2, artifact_desc2)
                            except:
                                self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")
                            
                            artID_skype = ccase.getArtifactTypeID(artifact_name2)
                            artID_skype_evt = ccase.getArtifactType(artifact_name2)
                            #
                            resultSet3 = stmt3.executeQuery("select guid, identity, dispname,  datetime(start_timestamp, 'unixepoch') 'StartTime', ip_address, call_duration from callmembers ORDER by StartTime asc;")
                            resultSet2 = stmt2.executeQuery("SELECT count(*) 'Count' from callmembers;")
                            if resultSet2.getInt("Count") > 0:
                                message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                                    "Skype Analyzer", skypename + " had " + str(resultSet2.getInt("Count")) + " calls", str(msgcounter))
                                IngestServices.getInstance().postMessage(message)
                                msgcounter+=1
                                
                                try:
                                    attribute_name = "TSK_SKYPE_CALL_IDENTITY"
                                    attribute_name2 = "TSK_SKYPE_CALL_TIME"
                                    attribute_name3 = "TSK_SKYPE_CALL_GUID"
                                    attribute_name4 = "TSK_SKYPE_CALL_DURATION"
                                    attribute_name5 = "TSK_SKYPE_CALL_IP"
                                    attribute_name6 = "TSK_SKYPE_CALL_DISPLAYNAME"
                                    attID_ex1 = ccase.addArtifactAttributeType(attribute_name2, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Time")
                                    attID_ex2 = ccase.addArtifactAttributeType(attribute_name, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Person")
                                    attID_ex3 = ccase.addArtifactAttributeType(attribute_name3, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "CallGUID")
                                    attID_ex4 = ccase.addArtifactAttributeType(attribute_name4, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Duration (Min)")
                                    attID_ex5 = ccase.addArtifactAttributeType(attribute_name5, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "IP Address")
                                    attID_ex6 = ccase.addArtifactAttributeType(attribute_name6, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "DisplayNamne")
                                except:
                                    pass
                                while resultSet3.next():
                                    if self.context.isJobCancelled():
                                        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                                            "Skype Analyzer", "ID : Cancelled", str(msgcounter))
                                        IngestServices.getInstance().postMessage(message)
                                        msgcounter+=1
                                        return IngestModule.ProcessResult.OK
                                    art = file.newArtifact(artID_skype)
                                    identity = resultSet3.getString("identity")
                                    time = resultSet3.getString("StartTime")
                                    guid = resultSet3.getString("guid")
                                    ip = resultSet3.getString("ip_address")
                                    display = resultSet3.getString("dispname")
                                    durtemp = resultSet3.getInt("call_duration")
                                    duration = durtemp / 60
                                    #Time
                                    attID_ex1 = ccase.getAttributeType("TSK_SKYPE_CALL_TIME")
                                    art.addAttribute(BlackboardAttribute(attID_ex1, SkypeDbIngestModuleFactory.moduleName, time))
                                    #IDENTITY
                                    attID_ex1 = ccase.getAttributeType("TSK_SKYPE_CALL_IDENTITY")
                                    art.addAttribute(BlackboardAttribute(attID_ex1, SkypeDbIngestModuleFactory.moduleName, identity))
                                    #DISPLAYNAME
                                    attID_ex1 = ccase.getAttributeType("TSK_SKYPE_CALL_DISPLAYNAME")
                                    art.addAttribute(BlackboardAttribute(attID_ex1, SkypeDbIngestModuleFactory.moduleName, display))
                                    #CALL GUID
                                    attID_ex1 = ccase.getAttributeType("TSK_SKYPE_CALL_GUID")
                                    art.addAttribute(BlackboardAttribute(attID_ex1, SkypeDbIngestModuleFactory.moduleName, guid))
                                    #DURATION
                                    attID_ex1 = ccase.getAttributeType("TSK_SKYPE_CALL_DURATION")
                                    art.addAttribute(BlackboardAttribute(attID_ex1, SkypeDbIngestModuleFactory.moduleName, str(duration)))
                                    #IP Address
                                    attID_ex1 = ccase.getAttributeType("TSK_SKYPE_CALL_IP")
                                    art.addAttribute(BlackboardAttribute(attID_ex1, SkypeDbIngestModuleFactory.moduleName, ip))
                                IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(SkypeDbIngestModuleFactory.moduleName, \
                                    artID_skype_evt, None))
                            else:
                                message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                                    "Skype Analyzer", skypename + " has no calls", str(msgcounter))
                                IngestServices.getInstance().postMessage(message)
                                msgcounter+=1
                            
                        else:
                            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                                    "Skype Analyzer","No accounts found in" + file.getName(), str(msgcounter))
                            IngestServices.getInstance().postMessage(message)
                            msgcounter+=1
                    except SQLException as e:
                        self.log(Level.INFO, "SQL Error: " + e.getMessage() )
                except SQLException as e:
                            self.log(Level.INFO, "Error querying database " + file.getName() + " (" + e.getMessage() + ")")
                       #
                    
                    
                    
                # Clean up
                stmt.close()
                stmt2.close()
                stmt3.close()
                stmt4.close()
                stmt5.close()
                dbConn.close()
                os.remove(lclDbPath)
                
            else:
                message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                    "Skype Analyzer","Not a SQLite Database - Missing magic number" , str(msgcounter ))
                IngestServices.getInstance().postMessage(message)
                msgcounter+=1
                #return IngestModule.ProcessResult.ERROR
                
            
            
        # After all databases, post a message to the ingest messages in box.
        if numFiles==0:
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Skype Analyzer", "Nothing to analyze ", str(msgcounter))
            IngestServices.getInstance().postMessage(message)
            msgcounter+=1
        else:
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Skype Analyzer", "Analyzed %d files" % fileCount, str(msgcounter))
            IngestServices.getInstance().postMessage(message)
            msgcounter+=1
        return IngestModule.ProcessResult.OK