# This python autopsy module will parse the WMI database for Recently used apps.  
# A sqlite database that contains the recently used apps will be created 
# then imported into the extracted view section of Autopsy.
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

# CCM_RecentlyUsed Apps Parser.
# March 2017
# 
# Comments 
#   Version 1.0 - Initial version - March 2017
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


# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class ParseRecentlyUsedAppsIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Parse CCM Recently Used Apps"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Parses CCM Recently Used Apps"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ParseRecentlyUsedAppsIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class ParseRecentlyUsedAppsIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(ParseRecentlyUsedAppsIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context

        # Get path to EXE based on where this script is run from.
        # Assumes EXE is in same folder as script
        # Verify it is there before any ingest starts
        self.path_to_recentApps_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "show_ccm_recentlyusedapps.exe")
        if not os.path.exists(self.path_to_recentApps_exe):
            raise IngestModuleException("show_ccm_recentlyusedapps.exe was not found in module folder")
        
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
        self.parse_recentApps(dataSource, progressBar)
        self.log(Level.INFO, "ending process, Just before call to parse_safari_history")
        
        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "CCM Recently Used Apps", " CCM Recently Used Apps Have Been Analyzed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
		
    def parse_recentApps(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
       # Set the database to be read to the once created by the prefetch parser program
        skCase = Case.getCurrentCase().getSleuthkitCase();
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "%", "/Windows/System32/wbem/Repository/")
        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;

		# Create Event Log directory in temp directory, if it exists then continue on processing		
        Temp_Dir = Case.getCurrentCase().getTempDirectory()
        self.log(Level.INFO, "create Directory " + Temp_Dir)
        try:
		    os.mkdir(Temp_Dir + "\Recently_Used")
        except:
		    self.log(Level.INFO, "Recently Used Directory already exists " + Temp_Dir)
			
        # Write out each Event Log file to the temp directory
        for file in files:
            
            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            #self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            if (file.getName() == '.' or file.getName() == '..'):
                self.log(Level.INFO, "Parent or Root Directory File not writing")
            else:
                # Save the DB locally in the temp folder. use file id as name to reduce collisions
                lclDbPath = os.path.join(Temp_Dir + "\Recently_Used", file.getName())
                ContentUtils.writeToFile(file, File(lclDbPath))

        self.log(Level.INFO, "Running prog ==> " + self.path_to_recentApps_exe + " win7 " + Temp_Dir + "\Recently_Used " + " " + \
                                     Temp_Dir + "\Recently_Used\\recentlyUsedApps.db3")
        pipe = Popen([self.path_to_recentApps_exe, "win7", Temp_Dir + "\Recently_Used", Temp_Dir + "\Recently_Used\\recentlyUsedApps.db3"], stdout=PIPE, stderr=PIPE)
        
        out_text = pipe.communicate()[0]
        self.log(Level.INFO, "Output from run is ==> " + out_text) 

        lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory() + "\Recently_Used", "recentlyUsedApps.db3")        
        if ("Exiting" in out_text):
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                "CCM Recently Used Apps", " Error in CCM Recently Used Apps module " )
            IngestServices.getInstance().postMessage(message)
        else:
            # Add custom Artifact to blackboard
            try:
               self.log(Level.INFO, "Begin Create New Artifacts ==> TSK_CCM_RECENTLY_USED_APPS")
               artID_art = skCase.addArtifactType("TSK_CCM_RECENTLY_USED_APPS", "WMI Recently Used Apps")
            except:		
               self.log(Level.INFO, "Artifacts Creation Error, artifact TSK_CCM_RECENTLY_USED_APPS exists. ==> ")

            # Add Custom attributes to blackboard
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_EXPLORER_FILE_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Explorer File Name")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, Explorer File Name ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_FILE_SIZE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "File Size")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, File Size ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_LAST_USED_TIME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Last Used Time")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, Last Used Time ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_TIME_ZONE_OFFSET", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Time Zone Offset")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, Time Zone Offset ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_LAUNCH_COUNT", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Launch Count")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, Launch Count ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_ORIG_FILE_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Original File Name")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, Original File Name ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_FILE_DESC", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "File Description")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, File Description ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_PROD_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Product Name")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, Product Name ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_PROD_VERSION", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Product Version")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, Product Version ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_FILE_VERSION", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "File Version")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, File Version ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_ADDITIONAL_PROD_CODES", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Additional Product Codes")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, Additional Product Codes ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_MSI_VERSION", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "MSI Version")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, MSI Version ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_MSI_DISPLAY_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "MSI Display Name")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, MSI Display Name ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_PRODUCT_CODE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Product Code")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, Product Code ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_SOFTWARE_PROP_HASH", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Software Property Hash")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, Software Property Hash ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_PROD_LANG", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Product Language")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, Product Language ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_FILE_PROP_HASH", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "File Property Hash")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, File Property Hash ==> ")
            try:
               attID_efn = skCase.addArtifactAttributeType("TSK_MSI_PUBLISHER", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "MSI Publisher")
            except:		
                 self.log(Level.INFO, "Attributes Creation Error, MSI Publisher ==> ")

            for file in files:
               if (file.getName() == "OBJECTS.DATA"):

                    # Open the DB using JDBC
                    lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory() + "\Recently_Used", "recentlyUsedApps.db3")
                    self.log(Level.INFO, "Path the recentlyUsedApps.db3 database file created ==> " + lclDbPath)
                    try: 
                       Class.forName("org.sqlite.JDBC").newInstance()
                       dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
                    except SQLException as e:
                       self.log(Level.INFO, "Could not open database file (not SQLite) recentlyUsedApps.db3 (" + e.getMessage() + ")")
                       return IngestModule.ProcessResult.OK
                    
                    # Query the history_visits table in the database and get all columns. 
                    try:
                       stmt = dbConn.createStatement()
                       recently_used_sql = "select FolderPath 'TSK_PATH', ExplorerFileName 'TSK_EXPLORER_FILE_NAME', " + \
                                           "FileSize 'TSK_FILE_SIZE', LastUserName 'TSK_USER_ID', strftime('%s',LastUsedTime) " + \
                                           "'TSK_LAST_USED_TIME', TimeZoneOffset 'TSK_TIME_ZONE_OFFSET', LaunchCount " + \
                                           "'TSK_LAUNCH_COUNT', OriginalFileName 'TSK_ORIG_FILE_NAME', FileDescription " + \
                                           "'TSK_FILE_DESC', CompanyName 'TSK_ORGANIZATION', ProductName 'TSK_PROD_NAME', " + \
                                           "ProductVersion 'TSK_PROD_VERSION', FileVersion 'TSK_FILE_VERSION', " + \
                                           "AdditionalProductCodes 'TSK_ADDITIONAL_PROD_CODES', msiVersion " + \
                                           "'TSK_MSI_VERSION', msiDisplayName 'TSK_MSI_DISPLAY_NAME', " + \
                                           "ProductCode 'TSK_PRODUCT_CODE', SoftwarePropertiesHash " + \
                                           "'TSK_SOFTWARE_PROP_HASH', ProductLanguage 'TSK_PROD_LANG', " + \
                                           "FilePropertiesHash 'TSK_FILE_PROP_HASH', msiPublisher 'TSK_MSI_PUBLISHER' " + \
                                           "from recently_used;"
                       self.log(Level.INFO, recently_used_sql)
                       resultSet = stmt.executeQuery(recently_used_sql)
                       self.log(Level.INFO, "query recently_used table")
                    except SQLException as e:
                       self.log(Level.INFO, "Error querying database for recently_used table (" + e.getMessage() + ")")
                       return IngestModule.ProcessResult.OK

                    artID_hst = skCase.getArtifactTypeID("TSK_CCM_RECENTLY_USED_APPS")
                    artID_hst_evt = skCase.getArtifactType("TSK_CCM_RECENTLY_USED_APPS")

                    meta = resultSet.getMetaData()
                    columncount = meta.getColumnCount()
                    column_names = []
                    self.log(Level.INFO, "Number of Columns in the table ==> " + str(columncount))
                    for x in range (1, columncount + 1):
                        self.log(Level.INFO, "Column Name ==> " + meta.getColumnLabel(x))
                        column_names.append(meta.getColumnLabel(x))
                    
                    self.log(Level.INFO, "All Columns ==> " + str(column_names))
                    # Cycle through each row and create artifacts
                    while resultSet.next():
                       try: 
                           #self.log(Level.INFO, SQL_String_1)
                           self.log(Level.INFO, "Artifact Is ==> " + str(artID_hst))
                           
                           art = file.newArtifact(artID_hst)
                           self.log(Level.INFO, "Inserting attribute URL")
                           for col_name in column_names:
                               attID_ex1 = skCase.getAttributeType(col_name)
                               self.log(Level.INFO, "Inserting attribute ==> " + str(attID_ex1))
                               self.log(Level.INFO, "Attribute Type ==> " + str(attID_ex1.getValueType()))
                               if attID_ex1.getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING:
                                    try:
                                        art.addAttribute(BlackboardAttribute(attID_ex1, ParseRecentlyUsedAppsIngestModuleFactory.moduleName, resultSet.getString(col_name)))
                                    except:		
                                        self.log(Level.INFO, "Attributes String Creation Error, " + col_name + " ==> ")
                               elif attID_ex1.getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER:
                                    try:
                                        art.addAttribute(BlackboardAttribute(attID_ex1, ParseRecentlyUsedAppsIngestModuleFactory.moduleName, resultSet.getInt(col_name)))
                                    except:		
                                        self.log(Level.INFO, "Attributes Integer Creation Error, " + col_name + " ==> ")
                               elif attID_ex1.getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG:
                                    try:
                                        art.addAttribute(BlackboardAttribute(attID_ex1, ParseRecentlyUsedAppsIngestModuleFactory.moduleName, resultSet.getInt(col_name)))
                                    except:		
                                        self.log(Level.INFO, "Attributes Long Creation Error, " + col_name + " ==> ")
                               elif attID_ex1.getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE:
                                    try:
                                        art.addAttribute(BlackboardAttribute(attID_ex1, ParseRecentlyUsedAppsIngestModuleFactory.moduleName, resultSet.getInt(col_name)))
                                    except:		
                                        self.log(Level.INFO, "Attributes Double Creation Error, " + col_name + " ==> ")
                               elif attID_ex1.getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.BYTE:
                                    try:
                                        art.addAttribute(BlackboardAttribute(attID_ex1, ParseRecentlyUsedAppsIngestModuleFactory.moduleName, resultSet.getString(col_name)))
                                    except:		
                                        self.log(Level.INFO, "Attributes Byte Creation Error, " + col_name + " ==> ")
                               else:
                                    try:
                                        art.addAttribute(BlackboardAttribute(attID_ex1, ParseRecentlyUsedAppsIngestModuleFactory.moduleName, int(resultSet.getString(col_name))))
                                    except:		
                                        self.log(Level.INFO, "Attributes Datatime Creation Error, " + col_name + " ==> ")

                       except SQLException as e:
                           self.log(Level.INFO, "Error getting values from web_history table (" + e.getMessage() + ")")

                    IngestServices.getInstance().fireModuleDataEvent(
                           ModuleDataEvent(ParseRecentlyUsedAppsIngestModuleFactory.moduleName, artID_hst_evt, None))

                    stmt.close()
                    dbConn.close()

        # Clean up
        try:
           os.remove(lclDbPath)
        except:
		   self.log(Level.INFO, "removal of Recently Used database failed ")
		#Clean up EventLog directory and files
        for file in files:
           try:
              os.remove(Temp_Dir + "\\Recently_Used" + "\\" + file.getName())
           except:
              self.log(Level.INFO, "removal of Recently Used files failed " + Temp_Dir + "\\" + file.getName())
        try:
           os.rmdir(Temp_Dir + "\Recently_Used")		
        except:
		   self.log(Level.INFO, "removal of recently used directory failed " + Temp_Dir)

