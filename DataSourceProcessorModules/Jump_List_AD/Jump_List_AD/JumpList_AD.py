# This python autopsy module will export the JumpList AutoDestinations and then call
# the command line version of the Export_JL_Ad program.  A sqlite database that
# contains the JumpList information is created then imported into the extracted
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

# Event Log module to parse the Windows Event Logs.
# March 2016
# 
# Comments 
#   Version 1.0 - Initial version - April 2016
#   Version 1.1 - Added custom artifacts/attributes - August 30, 2016
# 

import jarray
import inspect
import os
import subprocess

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
class JumpListADDbIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "JumpList AD"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Parses JumpList Auto Dest Files"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return JumpListADDbIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class JumpListADDbIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(JumpListADDbIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self.List_Of_Events = []

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context

        # Get path to EXE based on where this script is run from.
        # Assumes EXE is in same folder as script
        # Verify it is there before any ingest starts
        self.path_to_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "export_jl_ad.exe")
        self.path_to_app_id_db = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Jump_List_App_Ids.db3")
        if not os.path.exists(self.path_to_exe):
            raise IngestModuleException("EXE was not found in module folder")
        
        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException(IngestModule(), "Oh No!")
        pass

    # Where the analysis is done.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html
    def process(self, dataSource, progressBar):

        # Check to see if the artifacts exist and if not then create it, also check to see if the attributes
		# exist and if not then create them
        skCase = Case.getCurrentCase().getSleuthkitCase();
        skCase_Tran = skCase.beginTransaction()
        try:
             self.log(Level.INFO, "Begin Create New Artifacts")
             artID_jl_ad = skCase.addArtifactType( "TSK_JL_AD", "Jump List Auto Dest")
        except:		
             self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")
             artID_jl_ad = skCase.getArtifactTypeID("TSK_JL_AD")

        try:
            attID_jl_fn = skCase.addArtifactAttributeType("TSK_JLAD_FILE_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "JumpList File Name")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, JL AD File Name. ==> ")
        try:
            attID_jl_fg = skCase.addArtifactAttributeType("TSK_JLAD_FILE_DESCRIPTION", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "File Description")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, File Description. ==> ")
        try:
            attID_jl_in = skCase.addArtifactAttributeType("TSK_JLAD_ITEM_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Item Name")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Item Name. ==> ")
        try:
            attID_jl_cl = skCase.addArtifactAttributeType("TSK_JLAD_COMMAND_LINE_ARGS", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Command Line Args")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Command Line Arguments. ==> ")
        try:
            attID_jl_dt = skCase.addArtifactAttributeType("TSK_JLAD_Drive Type", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, "Drive Type")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Drive Type. ==> ")
        try:
            attID_jl_dsn = skCase.addArtifactAttributeType("TSK_JLAD_DRIVE_SERIAL_NUMBER", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, "Drive Serial Number")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Drive Serial Number. ==> ")
        try:
            attID_jl_des = skCase.addArtifactAttributeType("TSK_JLAD_DESCRIPTION", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Description")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Description. ==> ")
        try:
            attID_jl_evl = skCase.addArtifactAttributeType("TSK_JLAD_ENVIRONMENT_VARIABLES_LOCATION", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Env Var Location")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Env Var Location. ==> ")
        try:
            attID_jl_fat = skCase.addArtifactAttributeType("TSK_JLAD_FILE_ACCESS_TIME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "File Access Time")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, File Access Time. ==> ")
        try:
            attID_jl_faf = skCase.addArtifactAttributeType("TSK_JLAD_FILE_ATTRIBUTE_FLAGS", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, "File Attribute Flags")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, File Attribute Flags. ==> ")
        try:
            attID_jl_fct = skCase.addArtifactAttributeType("TSK_JLAD_FILE_CREATION_TIME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "File Creation Time")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, File Creation Time. ==> ")
        try:
            attID_jl_fmt = skCase.addArtifactAttributeType("TSK_JLAD_FILE_MODIFICATION_TIME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "File Modification Time")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, File Modification Time. ==> ")
        try:
            attID_jl_fs = skCase.addArtifactAttributeType("TSK_JLAD_FILE_SIZE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, "File Size")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, File Size. ==> ")
        try:
            attID_jl_ic = skCase.addArtifactAttributeType("TSK_JLAD_ICON_LOCATION", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Icon Location")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Icon Location. ==> ")
        try:
            attID_jl_ltid = skCase.addArtifactAttributeType("TSK_JLAD_LINK_TARGET_IDENTIFIER_DATA", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Link Target Identifier Data")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Link Target Identifier Data. ==> ")
        try:
            attID_jl_lp = skCase.addArtifactAttributeType("TSK_JLAD_LOCAL_PATH", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Local Path")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, File Modification Time. ==> ")
        try:
            attID_jl_mi = skCase.addArtifactAttributeType("TSK_JLAD_FILE_MACHINE_IDENTIFIER", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Machine Identifier")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Machine Identifier. ==> ")
        try:
            attID_jl_np = skCase.addArtifactAttributeType("TSK_JLAD_NETWORK_PATH", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Network Path")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Network Path. ==> ")
        try:
            attID_jl_rp = skCase.addArtifactAttributeType("TSK_JLAD_RELATIVE_PATH", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Relative Path")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Relative Path. ==> ")
        try:
            attID_jl_vl = skCase.addArtifactAttributeType("TSK_JLAD_VOLUME_LABEL", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Volume Label")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Volume Label. ==> ")
        try:
            attID_jl_wc = skCase.addArtifactAttributeType("TSK_JLAD_WORKING_DIRECTORY", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Working Directory")
        except:		
             self.log(Level.INFO, "Attributes Creation Error, Working Directory. ==> ")

        #self.log(Level.INFO, "Get Artifacts after they were created.")
        # Get the new artifacts and attributes that were just created
        artID_jl_ad = skCase.getArtifactTypeID("TSK_JL_AD")
        artID_jl_ad_evt = skCase.getArtifactType("TSK_JL_AD")
        attID_jl_fn = skCase.getAttributeType("TSK_JLAD_FILE_NAME")
        attID_jl_fg = skCase.getAttributeType("TSK_JLAD_FILE_DESCRIPTION")
        attID_jl_in = skCase.getAttributeType("TSK_JLAD_ITEM_NAME")			 
        attID_jl_cl = skCase.getAttributeType("TSK_JLAD_COMMAND_LINE_ARGS")
        attID_jl_dt = skCase.getAttributeType("TSK_JLAD_Drive Type")
        attID_jl_dsn = skCase.getAttributeType("TSK_JLAD_DRIVE_SERIAL_NUMBER")
        attID_jl_des = skCase.getAttributeType("TSK_JLAD_DESCRIPTION")
        attID_jl_evl = skCase.getAttributeType("TSK_JLAD_ENVIRONMENT_VARIABLES_LOCATION")
        attID_jl_fat = skCase.getAttributeType("TSK_JLAD_FILE_ACCESS_TIME")
        attID_jl_faf = skCase.getAttributeType("TSK_JLAD_FILE_ATTRIBUTE_FLAGS")
        attID_jl_fct = skCase.getAttributeType("TSK_JLAD_FILE_CREATION_TIME")
        attID_jl_fmt = skCase.getAttributeType("TSK_JLAD_FILE_MODIFICATION_TIME")
        attID_jl_fs = skCase.getAttributeType("TSK_JLAD_FILE_SIZE")
        attID_jl_ic = skCase.getAttributeType("TSK_JLAD_ICON_LOCATION")
        attID_jl_ltid = skCase.getAttributeType("TSK_JLAD_LINK_TARGET_IDENTIFIER_DATA")
        attID_jl_lp = skCase.getAttributeType("TSK_JLAD_LOCAL_PATH")
        attID_jl_mi = skCase.getAttributeType("TSK_JLAD_FILE_MACHINE_IDENTIFIER")
        attID_jl_np = skCase.getAttributeType("TSK_JLAD_NETWORK_PATH")
        attID_jl_rp = skCase.getAttributeType("TSK_JLAD_RELATIVE_PATH")
        attID_jl_vl = skCase.getAttributeType("TSK_JLAD_VOLUME_LABEL")
        attID_jl_wd = skCase.getAttributeType("TSK_JLAD_WORKING_DIRECTORY")
        
        #self.log(Level.INFO, "Artifact id for TSK_PREFETCH ==> " + str(artID_pf))
        
        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
        # Find the Windows Event Log Files
        files = []		
        
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "%.automaticDestinations-ms")

        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0;
		
        # Create Event Log directory in temp directory, if it exists then continue on processing		
        Temp_Dir = Case.getCurrentCase().getTempDirectory()
        self.log(Level.INFO, "create Directory " + Temp_Dir + "\JL_AD")
        try:
		    os.mkdir(Temp_Dir + "\JL_AD")
        except:
		    self.log(Level.INFO, "JL_AD Directory already exists " + Temp_Dir)
			
        # Write out each Event Log file to the temp directory
        for file in files:
            
            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            #self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Temp_Dir + "\JL_AD", file.getName())
            ContentUtils.writeToFile(file, File(lclDbPath))
                        

        # Example has only a Windows EXE, so bail if we aren't on Windows
        if not PlatformUtil.isWindowsOS(): 
            self.log(Level.INFO, "Ignoring data source.  Not running on Windows")
            return IngestModule.ProcessResult.OK

        # Run the EXE, saving output to a sqlite database
        self.log(Level.INFO, "Running program on data source parm 1 ==> " + Temp_Dir + "\JL_AD" + "  Parm 2 ==> " + Temp_Dir + "\JL_AD.db3")
        output = subprocess.Popen([self.path_to_exe, Temp_Dir + "\JL_AD", Temp_Dir + "\JL_AD.db3", self.path_to_app_id_db], stdout=subprocess.PIPE).communicate()[0]
        
        
        #self.log(Level.INFO, "Output for the JL_AD program ==> " + output)
        self.log(Level.INFO, " Return code is ==> " + output)
 			
        # Set the database to be read to the one created by the Event_EVTX program
        lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), "JL_AD.db3")
        self.log(Level.INFO, "Path to the JL_AD database file created ==> " + lclDbPath)
                        
        # Open the DB using JDBC
        try: 
            Class.forName("org.sqlite.JDBC").newInstance()
            dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
        except SQLException as e:
            self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
            return IngestModule.ProcessResult.OK
            
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "%.automaticDestinations-ms")
            
        for file in files:
            file_name = os.path.splitext(file.getName())[0]
            self.log(Level.INFO, "File To process in SQL " + file_name + "  <<=====")
            # Query the contacts table in the database and get all columns. 
            try:
                stmt = dbConn.createStatement()
                SQL_Statement = "select File_Name, File_Description, Item_Name, command_line_arguments, drive_type, drive_serial_number, " + \
                                " description, environment_variables_location, file_access_time, file_attribute_flags, file_creation_time, " + \
                                " file_modification_time, file_size, icon_location, link_target_identifier_data, local_path, " + \
                                " machine_identifier, network_path, relative_path, volume_label, working_directory " + \
                                " from Automatic_destinations_JL where upper(File_Name) = upper('" + file_name + "');"
#                                " from Automatic_destinations_JL where File_Name||'.automaticDestinations-ms' = '" + file_name + "';"
                #self.log(Level.INFO, "SQL Statement " + SQL_Statement + "  <<=====")
            	resultSet = stmt.executeQuery(SQL_Statement)
            except SQLException as e:
                self.log(Level.INFO, "Error querying database for EventLogs table (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            # Cycle through each row and create artifacts
            while resultSet.next():
                try: 
                    # self.log(Level.INFO, "Result (" + resultSet.getString("File_Name") + ")")
                    # self.log(Level.INFO, "Result (" + resultSet.getString("Recovered_Record") + ")")
                    # self.log(Level.INFO, "Result (" + resultSet.getString("Computer_Name") + ")")
                    # self.log(Level.INFO, "Result (" + resultSet.getString("Event_Identifier") + ")")
                    # self.log(Level.INFO, "Result (" + resultSet.getString("Event_Identifier_Qualifiers") + ")")
                    # self.log(Level.INFO, "Result (" + resultSet.getString("Event_Level") + ")")
                    # self.log(Level.INFO, "Result (" + resultSet.getString("Event_Offset") + ")")
                    # self.log(Level.INFO, "Result (" + resultSet.getString("Identifier") + ")")
                    # self.log(Level.INFO, "Result (" + resultSet.getString("Event_Source_Name") + ")")
                    # self.log(Level.INFO, "Result (" + resultSet.getString("Event_User_Security_Identifier") + ")")
                    # self.log(Level.INFO, "Result (" + resultSet.getString("Event_Time") + ")")
                    # self.log(Level.INFO, "Result (" + resultSet.getString("Event_Time_Epoch") + ")")
                    # self.log(Level.INFO, "Result (" + resultSet.getString("Event_Detail_Text") + ")")
                
                    File_Name = resultSet.getString("File_Name")
                    File_Description = resultSet.getString("File_Description")
                    Item_Name = resultSet.getString("Item_Name")
                    Command_Line_Arguments = resultSet.getString("command_line_arguments")
                    Drive_Type = resultSet.getInt("drive_type")
                    Drive_Serial_Number = resultSet.getInt("drive_serial_number")
                    Description = resultSet.getString("description")
                    Environment_Variables_Location = resultSet.getString("environment_variables_location")
                    File_Access_Time = resultSet.getString("file_access_time")
                    File_Attribute_Flags = resultSet.getInt("file_attribute_flags")
                    File_Creation_Time = resultSet.getString("file_creation_time")
                    File_Modification_Time = resultSet.getString("file_modification_time")
                    File_Size = resultSet.getInt("file_size")
                    Icon_Location = resultSet.getString("icon_location")
                    Link_Target_Identifier_Data = resultSet.getString("link_target_identifier_data")
                    Local_Path = resultSet.getString("local_path")
                    Machine_Identifier = resultSet.getString("machine_identifier")
                    Network_Path = resultSet.getString("network_path")
                    Relative_Path = resultSet.getString("relative_path")
                    Volume_Label = resultSet.getString("volume_label")
                    Working_Directory = resultSet.getString("working_directory")                
                except SQLException as e:
                    self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")
        
                #fileManager = Case.getCurrentCase().getServices().getFileManager()
                #files = fileManager.findFiles(dataSource, Prefetch_File_Name)                
            
                #for file in files:
                    # Make artifact for TSK_PREFETCH,  this can happen when custom attributes are fully supported
                    #art = file.newArtifact(artID_pf)
                    # Make an artifact on the blackboard, TSK_PROG_RUN and give it attributes for each of the fields
			        # Not the proper way to do it but it will work for the time being.
                art = file.newArtifact(artID_jl_ad)

                # This is for when proper atributes can be created.			
                art.addAttributes(((BlackboardAttribute(attID_jl_fn, JumpListADDbIngestModuleFactory.moduleName, File_Name)), \
                                   (BlackboardAttribute(attID_jl_fg, JumpListADDbIngestModuleFactory.moduleName, File_Description)), \
                                   (BlackboardAttribute(attID_jl_in, JumpListADDbIngestModuleFactory.moduleName, Item_Name)), \
                                   (BlackboardAttribute(attID_jl_cl, JumpListADDbIngestModuleFactory.moduleName, Command_Line_Arguments)), \
                                   (BlackboardAttribute(attID_jl_dt, JumpListADDbIngestModuleFactory.moduleName, Drive_Type)), \
                                   (BlackboardAttribute(attID_jl_dsn, JumpListADDbIngestModuleFactory.moduleName, Drive_Serial_Number)), \
                                   (BlackboardAttribute(attID_jl_des, JumpListADDbIngestModuleFactory.moduleName, Description)), \
                                   (BlackboardAttribute(attID_jl_evl, JumpListADDbIngestModuleFactory.moduleName, Environment_Variables_Location)), \
                                   (BlackboardAttribute(attID_jl_fat, JumpListADDbIngestModuleFactory.moduleName, File_Access_Time)), \
                                   (BlackboardAttribute(attID_jl_faf, JumpListADDbIngestModuleFactory.moduleName, File_Attribute_Flags)), \
                                   (BlackboardAttribute(attID_jl_fct, JumpListADDbIngestModuleFactory.moduleName, File_Creation_Time)), \
                                   (BlackboardAttribute(attID_jl_fmt, JumpListADDbIngestModuleFactory.moduleName, File_Modification_Time)), \
                                   (BlackboardAttribute(attID_jl_fs, JumpListADDbIngestModuleFactory.moduleName, File_Size)), \
                                   (BlackboardAttribute(attID_jl_ic, JumpListADDbIngestModuleFactory.moduleName, Icon_Location)), \
                                   (BlackboardAttribute(attID_jl_ltid, JumpListADDbIngestModuleFactory.moduleName, Link_Target_Identifier_Data)), \
                                   (BlackboardAttribute(attID_jl_lp, JumpListADDbIngestModuleFactory.moduleName, Local_Path)), \
                                   (BlackboardAttribute(attID_jl_mi, JumpListADDbIngestModuleFactory.moduleName, Machine_Identifier)), \
                                   (BlackboardAttribute(attID_jl_np, JumpListADDbIngestModuleFactory.moduleName, Network_Path)), \
                                   (BlackboardAttribute(attID_jl_rp, JumpListADDbIngestModuleFactory.moduleName, Relative_Path)), \
                                   (BlackboardAttribute(attID_jl_vl, JumpListADDbIngestModuleFactory.moduleName, Volume_Label)), \
                                   (BlackboardAttribute(attID_jl_wd, JumpListADDbIngestModuleFactory.moduleName, Working_Directory))))
			
        # Fire an event to notify the UI and others that there are new artifacts  
        IngestServices.getInstance().fireModuleDataEvent(
            ModuleDataEvent(JumpListADDbIngestModuleFactory.moduleName, artID_jl_ad_evt, None))
                
        # Clean up
        skCase_Tran.commit()
        stmt.close()
        dbConn.close()
        os.remove(lclDbPath)
        #skCase.close()
			
		#Clean up EventLog directory and files
        for file in files:
            try:
			    os.remove(Temp_Dir + "\\" + file.getName())
            except:
			    self.log(Level.INFO, "removal of JL_AD file failed " + Temp_Dir + "\\" + file.getName())
        try:
             os.rmdir(Temp_Dir)		
        except:
		     self.log(Level.INFO, "removal of JL_AD directory failed " + Temp_Dir)
            
        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "JumpList AD", " JumpList AD Has Been Analyzed " )
        IngestServices.getInstance().postMessage(message)

        # Fire an event to notify the UI and others that there are new artifacts  
        IngestServices.getInstance().fireModuleDataEvent(
            ModuleDataEvent(JumpListADDbIngestModuleFactory.moduleName, artID_jl_ad_evt, None))
        
        return IngestModule.ProcessResult.OK
		
