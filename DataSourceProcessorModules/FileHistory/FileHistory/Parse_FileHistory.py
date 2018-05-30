# This python autopsy module will export the Catalog1.edb file and then call
# the command line version of the Export_FileHistory.  A sqlite database that
# contains the File History information is created then imported into the extracted
# view section of Autopsy.
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

# File History Parser module to parse the File History file for each user in windows.
# APril 2017
# 
# Comments 
#   Version 1.0 - Initial version - April 2017
# 

import jarray
import inspect
import os
import sys
from subprocess import Popen, PIPE
import shutil

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
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.coreutils import PlatformUtil
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.datamodel import ContentUtils


# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class ParseFileHistoryIngestModuleFactory(IngestModuleFactoryAdapter):

    moduleName = "Parse File History"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Module that parses the Windows File History for Autopsy"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ParseFileHistoryIngestModule()


# Data Source-level ingest module.  One gets created per data source.
class ParseFileHistoryIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(ParseFileHistoryIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self):
        self.context = None

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context

        # Get path to EXE based on where this script is run from.
        # Assumes EXE is in same folder as script
        # Verify it is there before any ingest starts
        self.path_to_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "export_FileHistory.exe")
        if not os.path.exists(self.path_to_exe):
            raise IngestModuleException("EXE was not found in module folder")

     
    # Where the analysis is done.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html
    def process(self, dataSource, progressBar):

 
        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        # Check to see if the artifacts exist and if not then create it, also check to see if the attributes
		# exist and if not then create them
        skCase = Case.getCurrentCase().getSleuthkitCase();
                
        # This will work in 4.0.1 and beyond
        # Use blackboard class to index blackboard artifacts for keyword search
        blackboard = Case.getCurrentCase().getServices().getBlackboard()

        try:
             self.log(Level.INFO, "Begin Create New Artifacts")
             artID_cat1 = skCase.addArtifactType( "TSK_FH_CATALOG_1", "File History Catalog 1")
        except:		
             self.log(Level.INFO, "Artifacts Creation Error, Catalog 1. ==> ")
             artID_cat1 = skCase.getArtifactTypeID("TSK_FH_CATALOG_1")
        try:
             self.log(Level.INFO, "Begin Create New Artifacts")
             artID_cat2 = skCase.addArtifactType( "TSK_FH_CATALOG_2", "File History Catalog 2")
        except:		
             self.log(Level.INFO, "Artifacts Creation Error, Catalog 2. ==> ")
             artID_cat2 = skCase.getArtifactTypeID("TSK_FH_CATALOG_2")
             
        # Create the attribute type, if it exists then catch the error
        try:
            attID_fh_pn = skCase.addArtifactAttributeType('TSK_FH_PATH', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Parent Path")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Prefetch Parent Path. ==> ")

        try:
            attID_fh_fn = skCase.addArtifactAttributeType('TSK_FH_FILE_NAME', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "File Name")			 
        except:		
             self.log(Level.INFO, "Attributes Creation Error, File Name. ==> ")

        try:
            attID_fh_fs = skCase.addArtifactAttributeType('TSK_FH_FILE_SIZE', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "File Size")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, File Size. ==> ")

        try:
            attID_fh_usn = skCase.addArtifactAttributeType('TSK_FH_USN_JOURNAL_ENTRY', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "USN Journal Entry")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, USN Journal Entry. ==> ")

        try:
            attID_fh_fc = skCase.addArtifactAttributeType('TSK_FH_FILE_CREATED', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "File Created")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, File Created. ==> ")

        try:
            attID_fh_fm = skCase.addArtifactAttributeType('TSK_FH_FILE_MODIFIED', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "File Modified")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, PF Execution DTTM 3. ==> ")

        try:
            attID_fh_bq = skCase.addArtifactAttributeType('TSK_FH_BACKUP_QUEUED', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Backup Queued")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Backup Queued ==> ")

        try:
            attID_fh_bc = skCase.addArtifactAttributeType('TSK_FH_BACKUP_CREATED', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Backup Created")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Backup Created ==> ")

        try:
            attID_fh_bcp = skCase.addArtifactAttributeType('TSK_FH_BACKUP_CAPTURED', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Backup Captured")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Backup Captured. ==> ")

        try:
            attID_fh_bu = skCase.addArtifactAttributeType('TSK_FH_BACKUP_UPDATED', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Backup Updated")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Backup Updated. ==> ")

        try:
            attID_fh_bv = skCase.addArtifactAttributeType('TSK_FH_BACKUP_VISIBLE', BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Backup Visible")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Backup Visible ==> ")

        self.log(Level.INFO, "Get Artifacts after they were created.")
        # Get the new artifacts and attributes that were just created
        #artID_wfh = skCase.getArtifactTypeID("TSK_PREFETCH")
        #artID_cat1 = skCase.getArtifactType("TSK_FH_CATALOG_1")
        #artID_cat2 = skCase.getArtifactType("TSK_FH_CATALOG_2")
        attID_fh_pn = skCase.getAttributeType("TSK_FH_PATH")
        attID_fh_fn = skCase.getAttributeType("TSK_FH_FILE_NAME")
        attID_fh_fs = skCase.getAttributeType("TSK_FH_FILE_SIZE")
        attID_fh_usn = skCase.getAttributeType("TSK_FH_USN_JOURNAL_ENTRY")
        attID_fh_fc = skCase.getAttributeType("TSK_FH_FILE_CREATED")
        attID_fh_fm = skCase.getAttributeType("TSK_FH_FILE_MODIFIED")
        attID_fh_bq = skCase.getAttributeType("TSK_FH_BACKUP_QUEUED")
        attID_fh_bc = skCase.getAttributeType("TSK_FH_BACKUP_CREATED")
        attID_fh_bcp = skCase.getAttributeType("TSK_FH_BACKUP_CAPTURED")
        attID_fh_bu = skCase.getAttributeType("TSK_FH_BACKUP_UPDATED")
        attID_fh_bv = skCase.getAttributeType("TSK_FH_BACKUP_VISIBLE")

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        # Find the file history files from the users folders
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "%edb", "%/Windows/FileHistory/%")
        
        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;
		
        # Create file history directory in temp directory, if it exists then continue on processing		
        Temp_Dir = Case.getCurrentCase().getTempDirectory() + "\File_History"
        self.log(Level.INFO, "create Directory " + Temp_Dir)
        try:
		    os.mkdir(Temp_Dir)
        except:
		    self.log(Level.INFO, "File_History Directory already exists " + Temp_Dir)
			
        # Write out each catalog esedb database to the temp directory
        for file in files:
            
            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            #self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Temp_Dir, file.getName() + "_" + str(file.getId()))
            db_name = os.path.splitext(file.getName())[0]
            lclSQLPath = os.path.join(Temp_Dir, db_name + "_" + str(file.getId()) + ".db3")
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
            # Run the EXE, saving output to a sqlite database
            self.log(Level.INFO, "Running program on data source parm 1 ==> " + self.path_to_exe + " " + lclDbPath + " " + lclSQLPath)
            pipe = Popen([self.path_to_exe, lclDbPath, lclSQLPath], stdout=PIPE, stderr=PIPE)
            
            out_text = pipe.communicate()[0]
            self.log(Level.INFO, "Output from run is ==> " + out_text)                
		
            if db_name == "Catalog1":
                artID_fh = skCase.getArtifactTypeID("TSK_FH_CATALOG_1")
                artID_fh_evt = skCase.getArtifactType("TSK_FH_CATALOG_1")
            else:
                artID_fh = skCase.getArtifactTypeID("TSK_FH_CATALOG_2")
                artID_fh_evt = skCase.getArtifactType("TSK_FH_CATALOG_2")

            userpath = file.getParentPath()
            username = userpath.split('/')
            self.log(Level.INFO, "Getting Username " + username[2]   )
        
            # Open the DB using JDBC
            try: 
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclSQLPath)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + lclSQLPath + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK
                
            # Query the contacts table in the database and get all columns. 
            try:
                stmt = dbConn.createStatement()
                SQL_Statement = "Select ParentName 'TSK_FH_PATH', Childname 'TSK_FH_FILE_NAME', " + \
                                  "Filesize 'TSK_FH_FILE_SIZE', " + \
                                  "usn 'TSK_FH_USN_JOURNAL_ENTRY', " + \
                                  "FileCreated 'TSK_FH_FILE_CREATED', filemodified 'TSK_FH_FILE_MODIFIED', " + \
                                  "tqueued 'TSK_FH_BACKUP_QUEUED', tcreated 'TSK_FH_BACKUP_CREATED', " + \
                                  "tcaptured 'TSK_FH_BACKUP_CAPTURED', tupdated 'TSK_FH_BACKUP_UPDATED', " + \
                                  "tvisible 'TSK_FH_BACKUP_VISIBLE' from file_history"
                self.log(Level.INFO, "SQL Statement --> " + SQL_Statement)
                resultSet = stmt.executeQuery(SQL_Statement)
            except SQLException as e:
                self.log(Level.INFO, "Error querying database for File_History table (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            # Cycle through each row and create artifacts
            while resultSet.next():
                try: 
                    #self.log(Level.INFO, "Result (" + resultSet.getString("Prefetch_File_Name") + ")")
                    FH_Path  = resultSet.getString("TSK_FH_PATH")
                    FH_File_Name = resultSet.getString("TSK_FH_FILE_NAME")
                    FH_Filesize = resultSet.getString("TSK_FH_FILE_SIZE")
                    FH_Usn = resultSet.getString("TSK_FH_USN_JOURNAL_ENTRY")
                    FH_FC = resultSet.getInt("TSK_FH_FILE_CREATED")
                    FH_FM = resultSet.getInt("TSK_FH_FILE_MODIFIED")
                    FH_BQ = resultSet.getInt("TSK_FH_BACKUP_QUEUED")
                    FH_BC = resultSet.getInt("TSK_FH_BACKUP_CREATED")
                    FH_BCP = resultSet.getInt("TSK_FH_BACKUP_CAPTURED")
                    FH_BU = resultSet.getInt("TSK_FH_BACKUP_UPDATED")
                    FH_BV = resultSet.getInt("TSK_FH_BACKUP_VISIBLE")
                except SQLException as e:
                    self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")

                # Make artifact for TSK_PREFETCH,  this can happen when custom attributes are fully supported
                art = file.newArtifact(artID_fh)
    

                # Add the attributes to the artifact.
                art.addAttributes(((BlackboardAttribute(attID_fh_pn, ParseFileHistoryIngestModuleFactory.moduleName, FH_Path)), \
                                  (BlackboardAttribute(attID_fh_fn, ParseFileHistoryIngestModuleFactory.moduleName, FH_File_Name)), \
                                  (BlackboardAttribute(attID_fh_fs, ParseFileHistoryIngestModuleFactory.moduleName, FH_Filesize)), \
                                  (BlackboardAttribute(attID_fh_usn, ParseFileHistoryIngestModuleFactory.moduleName, FH_Usn)), \
                                  (BlackboardAttribute(attID_fh_fc, ParseFileHistoryIngestModuleFactory.moduleName, FH_FC)), \
                                  (BlackboardAttribute(attID_fh_fm, ParseFileHistoryIngestModuleFactory.moduleName, FH_FM)), \
                                  (BlackboardAttribute(attID_fh_bq, ParseFileHistoryIngestModuleFactory.moduleName, FH_BQ)), \
                                  (BlackboardAttribute(attID_fh_bc, ParseFileHistoryIngestModuleFactory.moduleName, FH_BC)), \
                                  (BlackboardAttribute(attID_fh_bcp, ParseFileHistoryIngestModuleFactory.moduleName, FH_BCP)), \
                                  (BlackboardAttribute(attID_fh_bu, ParseFileHistoryIngestModuleFactory.moduleName, FH_BU)), \
                                  (BlackboardAttribute(attID_fh_bv, ParseFileHistoryIngestModuleFactory.moduleName, FH_BV)), \
                                  (BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_NAME.getTypeID(), \
                                    ParseFileHistoryIngestModuleFactory.moduleName, username[2]))))
                
                try:
                    #index the artifact for keyword search
                    blackboard.indexArtifact(art)
                except Blackboard.BlackboardException as e:
                    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())
                
            IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(ParseFileHistoryIngestModuleFactory.moduleName, artID_fh_evt, None))
            
            # Clean up
            stmt.close()
            dbConn.close()
            #os.remove(lclDbPath)
			
		#Clean up prefetch directory and files
        try:
             shutil.rmtree(Temp_Dir)		
        except:
		     self.log(Level.INFO, "removal of directory tree failed " + Temp_Dir)
            
        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Windows File History Parser", " Windows File History Has Been Parsed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
