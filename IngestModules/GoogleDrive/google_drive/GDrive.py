# This module extracts some data from identified Google Drive databases and organizes it in the Tree Viewer Window


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
# Google Drive Analyzer - tvdm
#

import jarray
import inspect
import shutil
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
class GDriveDbIngestModuleFactory(IngestModuleFactoryAdapter):

    moduleName = "Google Drive Analyzer - tvdm"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Identifies Google Drive databases and extracts information which could be used as indications"

    def getModuleVersionNumber(self):
        return "1.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return GDriveDbIngestModule()



class GDriveDbIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(GDriveDbIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self):
        self.context = None


    def startUp(self, context):
        self.context = context
       
        pass
        
        
        
    
    def process(self, dataSource, progressBar):

        
        
        msgcounter = 0
        global mama 
        progressBar.switchToIndeterminate()
        global ccase
        ccase = Case.getCurrentCase().getSleuthkitCase()
        blackboard = Case.getCurrentCase().getServices().getBlackboard()
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        accounts = fileManager.findFiles(dataSource, "sync_config.db")
        numFiles = len(accounts)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0

        for file in accounts:
            fileCount += 1
            progressBar.progress(fileCount)
            progressBar.progress("Google Drive Analyzer")
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK
            
            
            lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".db")
            ContentUtils.writeToFile(file, File(lclDbPath))
            
            #ContentUtils.writeToFile()
            binary_file = open(lclDbPath, "rb")
            data = binary_file.read(15)
            binary_file.close()
            if str(data) == "SQLite format 3":
                try: 
                    Class.forName("org.sqlite.JDBC").newInstance()
                    dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
                except SQLException as e:
                    message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, 
                        "Initial config database:", "Cannot open " + file.getName()+ " as SQLite", file.getName()+ " not a database")
                    #IngestServices.getInstance().postMessage(message)
                    pass
                    return IngestModule.ProcessResult.ERROR

                try:
                    stmt = dbConn.createStatement()
                    stmt2 = dbConn.createStatement()
                    stmt3 = dbConn.createStatement()
                    stmt4 = dbConn.createStatement()
                    stmt5 = dbConn.createStatement()
                    
                    try: 
                        resultSet1  = stmt.executeQuery("select data_value 'account' from data WHERE entry_key='user_email';")
                        resultSet2 = stmt2.executeQuery("select count(*) 'count' from data WHERE entry_key='user_email';")
                        resultSet4 = stmt4.executeQuery("select data_value from data where data_key ='rowkey';")
                        

                        GAccount = resultSet1.getString("account")
                        no_of_accounts = resultSet2.getInt("count")
                        
                        if no_of_accounts > 0:
                            gBase = fileManager.findFiles(dataSource, "snapshot.db", file.getParentPath())  
                            #ccase = Case.getCurrentCase().getSleuthkitCase()
                            artifact_name = "TSK_MSG_" + GAccount
                            artifact_desc = "Google Drive Account: " + GAccount
                            try:
                                #Try adding the Articaft Type
                                artID_Gdrive = ccase.addArtifactType(artifact_name, artifact_desc)
                                
                            except:
                                #do nothing
                                pass
                            artID_Gdrive = ccase.getArtifactTypeID(artifact_name)
                            artID_Gdrive_evt = ccase.getArtifactType(artifact_name)
                            
                            for gDatabase in gBase:
                                if str(file.getParentPath()) in str(gDatabase):
                                    lclDbPath2 = os.path.join(Case.getCurrentCase().getTempDirectory(),  str(GAccount) + ".db")
                                    ContentUtils.writeToFile(gDatabase, File(lclDbPath2))
                                    binary_file = open(lclDbPath2, "rb")
                                    data = binary_file.read(15)
                                    binary_file.close()
                                    if str(data) == "SQLite format 3":
                                        try: 
                                            Class.forName("org.sqlite.JDBC").newInstance()
                                            dbFiles = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath2)
                                            dbSMT = dbFiles.createStatement()
                                            dbSMT2 = dbFiles.createStatement()
                                            dbSMT3 = dbFiles.createStatement()
                                            dbSMT4 = dbFiles.createStatement()
                                            
                                        except SQLException as e:
                                            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                                                "Google Drive Analyzer","Cannot open " + file.getName()+ " as SQLite","FATAL")
                                            IngestServices.getInstance().postMessage(message)
                                            msgcounter+=1
                                            return IngestModule.ProcessResult.ERROR
                                        
                                        
                                        resultSet4 = dbSMT2.executeQuery("select count(filename) 'Count' from cloud_entry;")
                                        resultSet5 = dbSMT3.executeQuery("select child_doc_id, parent_doc_id from cloud_relations;")

                                        if resultSet4.getInt("Count") > 0:
                                            try:
                                                attribute_name = "TSK_GDRIVE_FILENAME"
                                                attribute_name2 = "TSK_GDRIVE_TIME"
                                                attribute_name3 = "TSK_GDRIVE_SIZE"
                                                attribute_name4 = "TSK_GDRIVE_SHARED"
                                                attribute_name5 = "TSK_GDRIVE_TYPE"
                                                attribute_name0 = "TSK_GDRIVE_PARENT"
                                                attID_ex0 = ccase.addArtifactAttributeType(attribute_name0, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Parent Directory")
                                                attID_ex1 = ccase.addArtifactAttributeType(attribute_name, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Filename or directory")
                                                attID_ex2 = ccase.addArtifactAttributeType(attribute_name2, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Modification date")
                                                attID_ex3 = ccase.addArtifactAttributeType(attribute_name3, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Size in KiB")
                                                attID_ex4 = ccase.addArtifactAttributeType(attribute_name4, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Shared with others")
                                                attID_ex5 = ccase.addArtifactAttributeType(attribute_name5, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Type")
                                            except:
                                                    pass
                                                    
                                            parent = ""
                                            mama = ""
                                            child =""
                                            ouder = ""
                                            papa = ""
                                            child2 = ""
                                            while resultSet5.next(): #Loop for the files within dbase - cloud_relations
                                                parent = resultSet5.getString("parent_doc_id")
                                                
                                                
                                                dbFiles = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath2)
                                                dbSMT6 = dbFiles.createStatement()
                                                resultSet6 = dbSMT6.executeQuery("select filename from cloud_entry where doc_id='" + str(parent) + "';")
                                                parentfilename = resultSet6.getString("filename")
                                                PathCheck = 0
                                                mama = ""
                                                papa = ""
                                                child = ""
                                                child = resultSet5.getString("child_doc_id")
                                                child2 = child
                                                teller = 0
                                                while PathCheck == 0:
                                                    teller +=1
                                                    try:
                                                        #Should work = gets the parent_doc_id from relations table
                                                        
                                                        try:
                                                            
                                                            dbSMT7 = dbFiles.createStatement()
                                                            resultSet10  = dbSMT7.executeQuery("select parent_doc_id from cloud_relations where child_doc_id = '" +str(child)+"';")
                                                            ouder = resultSet10.getString("parent_doc_id")
                                                        except:
                                                            break
                                                        try:
                                                            dbSMT7 = dbFiles.createStatement()
                                                            resultSet11 = dbSMT7.executeQuery("select filename from cloud_entry where doc_id = '" + str(ouder)+"';")
                                                            papa = resultSet11.getString("filename")
                                                        except:
                                                            break
                                                        if len(papa) == 0 or str(papa) == "root":
                                                            PathCheck = 1
                                                            mama = "[root]\\" + str(mama)
                                                            break
                                                        else:
                                                            tijdelijk = mama
                                                            mama = str(papa) + "\\" + str(tijdelijk)
                                                            child = ouder
                                                    except:
                                                        break
                                               
                                                SQLFiles = "select f.filename, datetime(f.modified, 'unixepoch') 'Time', f.size/1024 'KB', f.doc_id, CASE f.shared WHEN 0 THEN 'No' ELSE 'Yes' END Shared , CASE f.doc_type WHEN 0 THEN 'Directory' ELSE 'File' END Type from cloud_entry f, cloud_relations c where c.parent_doc_id ='"+ str(parent) +"' and f.doc_id='" + str(child2)+"' and f.doc_id=c.child_doc_id;"
                                                
                                                resultSet3 = dbSMT.executeQuery(SQLFiles)
                                                
                                                while resultSet3.next():
                                                    if self.context.isJobCancelled():
                                                        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "Canceling","Enumeration of files")
                                                        ngestServices.getInstance().postMessage(message)
                                                        msgcounter+=1
                                                        return IngestModule.ProcessResult.OK
                                                    
                                                    filename = resultSet3.getString("filename")
                                                    time = resultSet3.getString("Time")
                                                    Size = resultSet3.getString("KB")
                                                    sharing = resultSet3.getString("Shared")
                                                    filetype = resultSet3.getString("Type")
                                                    #
                                                    #
                                                    #
                                                    artifact_name = "TSK_MSG_" + GAccount
                                                    art = gDatabase.newArtifact(artID_Gdrive)
                                                    attID_ex0 = ccase.getAttributeType("TSK_GDRIVE_PARENT")
                                                    art.addAttribute(BlackboardAttribute(attID_ex1, GDriveDbIngestModuleFactory.moduleName, str(mama + "\\" +filename)))
                                                    attID_ex2 = ccase.getAttributeType("TSK_GDRIVE_TIME")
                                                    art.addAttribute(BlackboardAttribute(attID_ex2, GDriveDbIngestModuleFactory.moduleName, time))
                                                    attID_ex3 = ccase.getAttributeType("TSK_GDRIVE_SIZE")
                                                    art.addAttribute(BlackboardAttribute(attID_ex3, GDriveDbIngestModuleFactory.moduleName, Size))
                                                    attID_ex4 = ccase.getAttributeType("TSK_GDRIVE_SHARED")
                                                    art.addAttribute(BlackboardAttribute(attID_ex4, GDriveDbIngestModuleFactory.moduleName, sharing))
                                                    attID_ex5 = ccase.getAttributeType("TSK_GDRIVE_TYPE")
                                                    art.addAttribute(BlackboardAttribute(attID_ex5, GDriveDbIngestModuleFactory.moduleName, filetype))
                                                    IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(GDriveDbIngestModuleFactory.moduleName,  artID_Gdrive_evt, None))

                                                dbSMT6.close()
                                                
                                        else:
                                            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                                            "Google Drive Analyzer","No accounts found in" + file.getName(), "Error findings accounts")
                                            IngestServices.getInstance().postMessage(message)
                                            msgcounter+=1
                                            return IngestModule.ProcessResult.ERROR
                    except SQLException as e:
                        self.log(Level.INFO, "SQL Error: " + e.getMessage() )
                except SQLException as e:
                            self.log(Level.INFO, "Error querying database " + file.getName() + " (" + e.getMessage() + ")")
                       #
                    
                    
                    
                # Clean up
                try:
                    stmt.close()
                    stmt2.close()
                    stmt3.close()
                    stmt4.close()
                    stmt5.close()
                    
                    dbSMT.close()
                    dbConn.close()
                    os.remove(lclDbPath)
                    os.remove(lclDbPath2)
                except:
                    message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                                "Google Drive Analyzer","Unable to clean up", "Error - Cleanup")
                    #IngestServices.getInstance().postMessage(message)
                    msgcounter+=1
                
            else:
                message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                    "Google Drive Analyzer","Not a SQLite Database - Missing magic number" , "Not database")
                #IngestServices.getInstance().postMessage(message)
                msgcounter+=1
                return IngestModule.ProcessResult.ERROR
                
            
            
        # After all databases, post a message to the ingest messages in box.
        if numFiles==0:
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Google Drive Analyzer", "Info:", "Nothing to analyze ")
            #IngestServices.getInstance().postMessage(message)
            msgcounter+=1
        else:
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Google Drive Analyzer",  "Info:" , "Analyzed %d files" % fileCount)
            #IngestServices.getInstance().postMessage(message)
            msgcounter+=1
        return IngestModule.ProcessResult.OK