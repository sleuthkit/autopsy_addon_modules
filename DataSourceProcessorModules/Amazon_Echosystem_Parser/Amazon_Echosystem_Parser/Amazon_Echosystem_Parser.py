# This python autopsy module will parse the databases from an alexa image.
# Based on research by Brian Moran  
#
# Contact: Mark McKinnon [Mark [dot] McKinnon <at> Davenport [dot] edu]
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

# Parse databases from Alexa.
# October 2017
# 
# Comments 
#   Version 1.0 - Initial version - October 2017
# 

import jarray
import inspect
import os
from subprocess import Popen, PIPE
from urlparse import urlparse, parse_qs

from java.lang import Class
from java.lang import System
from java.sql  import DriverManager, SQLException
from java.util.logging import Level
from java.io import File
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.coreutils import PlatformUtil
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.datamodel import TskCoreException


# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class Alexa_DB_ParseIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Amazon Echosystem Parser"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Amazon Echosystem Parser"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return Alexa_DB_ParseIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class Alexa_DB_ParseIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(Alexa_DB_ParseIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        #self.local_settings = settings
        self.path_to_safari_exe = ""
        self.artifact_name = ""
        self.os_version = ""
        
    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context

        # Get path to EXE based on where this script is run from.
        # Assumes EXE is in same folder as script
        # Verify it is there before any ingest starts
        #self.path_to_safari_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plist_safari.exe")
        #if not os.path.exists(self.path_to_safari_exe):
        #    raise IngestModuleException("plist_safari.exe was not found in module folder")
        
        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException(IngestModule(), "Oh No!")
        pass

    # Where the analysis is done.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html
    def process(self, dataSource, progressBar):

        self.log(Level.INFO, "Starting to process, Just before call to parse_safari_history")

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        self.log(Level.INFO, "Starting 2 to process, Just before call to parse_safari_history")

        skCase = Case.getCurrentCase().getSleuthkitCase();

        head, tail = os.path.split(os.path.abspath(__file__)) 
        settings_db = head + "\\alexa_db.db3"

        #Start to process based on version of OS
        try: 
           Class.forName("org.sqlite.JDBC").newInstance()
           dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % settings_db)
        except SQLException as e:
           self.log(Level.INFO, "Could not open database file (not SQLite) macos_recents.db3 (" + e.getMessage() + ")")
           return IngestModule.ProcessResult.OK
        
        # Query the database table for unique file names 
        try:
           stmt = dbConn.createStatement()
           process_data_sql = "Select distinct file_name from alexa_databases"
           self.log(Level.INFO, process_data_sql)
           resultSet = stmt.executeQuery(process_data_sql)
           self.log(Level.INFO, "Query Database table for unique file names")
        except SQLException as e:
           self.log(Level.INFO, "Error querying database for unique file names")
           return IngestModule.ProcessResult.OK

        # Process all the artifacts based on version of the OS   
        while resultSet.next():
            fileManager = Case.getCurrentCase().getServices().getFileManager()
            files = fileManager.findFiles(dataSource, resultSet.getString("file_name"))
            numFiles = len(files)
            self.log(Level.INFO, "found " + str(numFiles) + " files for file_name ==> " + resultSet.getString("file_name"))
            progressBar.switchToDeterminate(numFiles)
            fileCount = 0;
                    
            for file in files:	
               # Open the DB using JDBC
               #lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), SQLite_DB)
               lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), file.getName() + "-" + str(file.getId()))
               ContentUtils.writeToFile(file, File(lclDbPath))

               #self.log(Level.INFO, "Path the prefetch database file created ==> " + lclDbPath)
               try: 
                   Class.forName("org.sqlite.JDBC").newInstance()
                   dbConn_x = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
                   self.log(Level.INFO, "Database ==> " + file.getName())
               except SQLException as e:
                   self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + "-" + str(file.getId()) + " (" + e.getMessage() + ")")
                   #return IngestModule.ProcessResult.OK
               
               try:
                  stmt_sql = dbConn.createStatement()
                  process_stmt_sql = "select artifact_name, artifact_description, sql_to_run from alexa_databases where file_name = '" + resultSet.getString("file_name") + "';"
                  self.log(Level.INFO, process_stmt_sql)
                  resultSet_sql = stmt_sql.executeQuery(process_stmt_sql)
                  self.log(Level.INFO, "Query Database table for sql statements")
               except SQLException as e:
                  self.log(Level.INFO, "Error querying database for sql_statements for file " + resultSet.getString("file_name"))
#                  return IngestModule.ProcessResult.OK

               # Process all the artifacts based on version of the OS   
               while resultSet_sql.next():
                   
                    try:
                       stmt_1 = dbConn_x.createStatement()
                       sql_to_run = resultSet_sql.getString("sql_to_run")
                       self.log(Level.INFO, sql_to_run)
                       resultSet_3 = stmt_1.executeQuery(sql_to_run)
                       self.log(Level.INFO, "query " + sql_to_run)
                    except SQLException as e:
                       self.log(Level.INFO, "Error querying database for " + resultSet.getString("file_name"))
                       continue
#                      return IngestModule.ProcessResult.OK

                    try:
                        #self.log(Level.INFO, "Begin Create New Artifacts")
                        artID_sql = skCase.addArtifactType(resultSet_sql.getString("artifact_name"), resultSet_sql.getString("artifact_description"))
                    except:		
                        self.log(Level.INFO, "Artifacts Creation Error, for artifact. ==> " + resultSet_sql.getString("artifact_name"))

                    artID_hst = skCase.getArtifactTypeID(resultSet_sql.getString("artifact_name"))
                    artID_hst_evt = skCase.getArtifactType(resultSet_sql.getString("artifact_name"))

                    meta = resultSet_3.getMetaData()
                    columncount = meta.getColumnCount()
                    column_names = []
                    self.log(Level.INFO, "Number of Columns in the table ==> " + str(columncount))
                    for x in range (1, columncount + 1):
                        self.log(Level.INFO, "Column Name ==> " + meta.getColumnLabel(x))
                        try:
                            attID_ex1 = skCase.addArtifactAttributeType("TSK_ALEXA_" + meta.getColumnLabel(x).upper(), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, meta.getColumnLabel(x))
                        except:		
                            self.log(Level.INFO, "Attributes Creation Error, " + "TSK_ALEXA_" + meta.getColumnLabel(x) + " ==> ")
                        column_names.append(meta.getColumnLabel(x))
                    
                    self.log(Level.INFO, "All Columns ==> " + str(column_names))
                    # Cycle through each row and create artifacts
                    while resultSet_3.next():
                       try: 
                           #self.log(Level.INFO, SQL_String_1)
                           self.log(Level.INFO, "Artifact Is ==> " + str(artID_hst))
                           
                           art = file.newArtifact(artID_hst)
                           self.log(Level.INFO, "Inserting attribute URL")
                           for col_name in column_names:
                               attID_ex1 = skCase.getAttributeType("TSK_ALEXA_" + col_name.upper())
                               self.log(Level.INFO, "Inserting attribute ==> " + str(attID_ex1))
                               self.log(Level.INFO, "Attribute Type ==> " + str(attID_ex1.getValueType()))
                               if attID_ex1.getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING:
                                    try:
                                        art.addAttribute(BlackboardAttribute(attID_ex1, Alexa_DB_ParseIngestModuleFactory.moduleName, resultSet_3.getString(col_name)))
                                    except:		
                                        self.log(Level.INFO, "Attributes String Creation Error, " + col_name + " ==> ")
                               elif attID_ex1.getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER:
                                    try:
                                        art.addAttribute(BlackboardAttribute(attID_ex1, Alexa_DB_ParseIngestModuleFactory.moduleName, resultSet_3.getInt(col_name)))
                                    except:		
                                        self.log(Level.INFO, "Attributes Integer Creation Error, " + col_name + " ==> ")
                               elif attID_ex1.getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG:
                                    try:
                                        art.addAttribute(BlackboardAttribute(attID_ex1, Alexa_DB_ParseIngestModuleFactory.moduleName, resultSet_3.getInt(col_name)))
                                    except:		
                                        self.log(Level.INFO, "Attributes Long Creation Error, " + col_name + " ==> ")
                               elif attID_ex1.getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE:
                                    try:
                                        art.addAttribute(BlackboardAttribute(attID_ex1, Alexa_DB_ParseIngestModuleFactory.moduleName, resultSet_3.getInt(col_name)))
                                    except:		
                                        self.log(Level.INFO, "Attributes Double Creation Error, " + col_name + " ==> ")
                               elif attID_ex1.getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.BYTE:
                                    try:
                                        art.addAttribute(BlackboardAttribute(attID_ex1, Alexa_DB_ParseIngestModuleFactory.moduleName, resultSet_3.getString(col_name)))
                                    except:		
                                        self.log(Level.INFO, "Attributes Byte Creation Error, " + col_name + " ==> ")
                               else:
                                    try:
                                        art.addAttribute(BlackboardAttribute(attID_ex1, Alexa_DB_ParseIngestModuleFactory.moduleName, resultSet_3.getReal(col_name)))
                                    except:		
                                        self.log(Level.INFO, "Attributes Datatime Creation Error, " + col_name + " ==> ")

                       except SQLException as e:
                           self.log(Level.INFO, "Error getting values from sql statement ==> " + resultSet_sql.getString("artifact_name"))

                    IngestServices.getInstance().fireModuleDataEvent(
                           ModuleDataEvent(Alexa_DB_ParseIngestModuleFactory.moduleName, artID_hst_evt, None))


                    stmt_1.close()
               stmt_sql.close()
               dbConn_x.close()

            
        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Mac OS Recent Artifacts", " Mac OS Recents Artifacts Have Been Analyzed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
		

      
       
       