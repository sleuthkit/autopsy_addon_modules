# This python autopsy module will create a VHD expandable volume and mount it.  
# It will then read a SQLite database of file extensions that can be exported to it
# and export those files matching the file extensions.  It will then unmount the 
# the vhd so it can be added back into an autopsy case. 
#
# Contact: Mark McKinnon [Mark [dot] McKinnon <at> gmail [dot] com]
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

# Create_Preview_Data_Container.py.
# November 2017
# 
# Comments 
#   Version 1.0 - Initial version - November 2017
#   Version 1.1 - Put quotes around path for diskpart script and add exit to find empty drive letter
#   Version 1.2 - Add try except block around creating and writing log file.
#   version 1.3 - Add creation of csv file to MdouleOutput directory
# 

import jarray
import inspect
import os
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
from org.sleuthkit.datamodel import TskData
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
class Crt_Preview_Data_ContainertModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Create Preview Data Container"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Create Preview Data Container in ModuleOu"
    
    def getModuleVersionNumber(self):
        return "1.3"
    
    def hasIngestJobSettingsPanel(self):
        return False

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return Crt_Preview_Data_ContainertModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class Crt_Preview_Data_ContainertModule(DataSourceIngestModule):

    _logger = Logger.getLogger(Crt_Preview_Data_ContainertModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
 
    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context

        #Show parameters that are passed in
        self.file_extension_db = os.path.join(os.path.dirname(os.path.abspath(__file__)), "File_Extensions.db3")
        if not os.path.exists(self.file_extension_db):
            raise IngestModuleException("File Extension Database Does not Exist")

     
        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException(IngestModule(), "Oh No!")
        pass

    # Where the analysis is done.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # See:x http://www.sleuthkit.org/sleuthkit/docs/jni-docs/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        # Set the status of the progress bar
        progressBar.progress("Creating/Mounting the Virtual Disk")
        
        # Set the database to be read to the once created by the prefetch parser program
        skCase = Case.getCurrentCase().getSleuthkitCase();
        
        # Create the directory to write the vhd file to
        mod_dir = Case.getCurrentCase().getModulesOutputDirAbsPath()
        vdisk_dir = os.path.join(mod_dir, "Preview_VHD")
        try:
            os.mkdir(vdisk_dir)
        except:
            self.log(Level.INFO, "Virtual disk directory already exists in Module Directory")
        vdisk_name = os.path.join(vdisk_dir, Case.getCurrentCase().getNumber() + "_preview.vhd")
        
        # Get the size of the image file in megs
        size_of_disk = dataSource.getSize() // 1048576
        self.log(Level.INFO, "size of disk is ==> " + str(size_of_disk))
        (vdisk_create_script, vdisk_unmount_script, vdisk_mount_script, drive_letter) = self.Create_Diskpart_Script(size_of_disk, vdisk_name)     
            
        # Run Diskpart using the scripts that will create a VHD
        # If disk already exists then just mount it otherwise create it, mount it and format it
        if os.path.exists(vdisk_name):
            self.log(Level.INFO, "Running prog ==> " + "diskpart.exe "  + " -S " + vdisk_mount_script)
            pipe = Popen(["diskpart.exe", "-S", vdisk_mount_script], stdout=PIPE, stderr=PIPE)
            out_text = pipe.communicate()[0]
            self.log(Level.INFO, "Output from run is ==> " + out_text)               
        else:        
            self.log(Level.INFO, "Running prog ==> " + "diskpart.exe "  + " -S " + vdisk_create_script)
            pipe = Popen(["diskpart.exe", "-S", vdisk_create_script], stdout=PIPE, stderr=PIPE)
            out_text = pipe.communicate()[0]
            self.log(Level.INFO, "Output from run is ==> " + out_text)               

        # Make the top level directory the datasource name
        try:
            data_source_dir = os.path.join(drive_letter + "\\", dataSource.getName())
            os.mkdir(data_source_dir)
        except:
            self.log(Level.INFO, "Data source Directory already exists")        
        
        # Create log file for the number of extensions found
        try:
            mod_log_file = os.path.join(vdisk_dir, "File_Extensions_Written_Log_" + dataSource.getName() + ".csv")
            self.log(Level.INFO, "Output Directory is ==> " + mod_log_file)
            mod_log = open(mod_log_file, "w")
            mod_log.write('Directory_In,File_Extension,Number_Of_Files_Written \n')
            out_log_file = os.path.join(drive_letter + "\\", "File_Extensions_Written_Log_" + dataSource.getName() + ".csv")
            self.log(Level.INFO, "Output Directory is ==> " + out_log_file)
            out_log = open(out_log_file, "w")
            out_log.write('Directory_In,File_Extension,Number_Of_Files_Written \n')
        except:
            self.log(Level.INFO, "Log File creation error")

        # Open the DB using JDBC
        try: 
            Class.forName("org.sqlite.JDBC").newInstance()
            dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % self.file_extension_db)
        except SQLException as e:
            self.log(Level.INFO, "Could not open File Extension database " + self.file_extension_db + " (" + e.getMessage() + ")")
            return IngestModule.ProcessResult.OK

        # Get all the file extensions that we want to find and export to the Preview Disk            
        try:
            stmt = dbConn.createStatement()
            SQL_Statement = "select Output_Directory, File_Extension from File_Extensions_To_Export"
            self.log(Level.INFO, "SQL Statement --> " + SQL_Statement)
            resultSet = stmt.executeQuery(SQL_Statement)
        except SQLException as e:
            self.log(Level.INFO, "Error querying database for File_Extensions_To_Export table (" + e.getMessage() + ")")
            return IngestModule.ProcessResult.OK
            
        # Cycle through each row and create artifacts
        while resultSet.next():
            try: 
                # Update the progress bar with the type of Document we are extracting
                progressBar.progress("Extracting " + resultSet.getString('Output_Directory') + " Files")
                
                fileManager = Case.getCurrentCase().getServices().getFileManager()
                files = fileManager.findFiles(dataSource, "%." + resultSet.getString("File_Extension"), "")
                numFiles = len(files)
                self.log(Level.INFO, "Number of files found for file extension " + resultSet.getString("File_Extension") + " ==> " + str(numFiles))

                try:
                    mod_log.write(resultSet.getString('Output_Directory') + "," + resultSet.getString("File_Extension") + "," + str(numFiles) + "\n")
                    out_log.write(resultSet.getString('Output_Directory') + "," + resultSet.getString("File_Extension") + "," + str(numFiles) + "\n")
                except:
                    self.log(Level.INFO, " Error Writing Log File ==> " + resultSet.getString('Output_Directory') + "," + resultSet.getString("File_Extension") + "," + str(numFiles) + "\n")
                    
                # Need to create log file here
                
                # Try and create directory to store files in, may already be created so we will ignore if it does
                try:
                    dir_to_write_to = os.path.join(data_source_dir, resultSet.getString('Output_Directory'))
                    if not os.path.exists(dir_to_write_to):
                        os.mkdir(dir_to_write_to)
                except:
                    self.log(Level.INFO, "Directory " + resultSet.getString('Output_Directory') + " already exists.")
                    
                # Write all the files to the vhd
                for file in files:
                    lclfile = os.path.join(dir_to_write_to, str(file.getId()) + "-" + file.getName())
                    #self.log(Level.INFO, "File to write ==> " + lclfile)
                    ContentUtils.writeToFile(file, File(lclfile))
            except:
                self.log(Level.INFO, "Error in processing sql statement")
                   
        # Close the log file
        try:
            mod_log.close()
            out_log.close()
        except:
            self.log(Level.INFO, "Error closing log files, they might not exist")        

        # Set the progress bar to unmounting
        progressBar.progress("Unmounting The Virtual Disk")
        
        # Run Diskpart using the scripts to unmount the VHD   
        self.log(Level.INFO, "Running prog ==> " + "diskpart.exe "  + " -S " + vdisk_unmount_script)
        pipe = Popen(["diskpart.exe", "-S", vdisk_unmount_script], stdout=PIPE, stderr=PIPE)
        out_text = pipe.communicate()[0]
        self.log(Level.INFO, "Output from run is ==> " + out_text)               

        # Clean up
        stmt.close()
        dbConn.close()
      	
		#Clean up prefetch directory and files
        try:
             shutil.rmtree(os.path.join(Case.getCurrentCase().getTempDirectory(), "vdisk_scripts"))		
        except:
		     self.log(Level.INFO, "removal of vdisk script directory failed " + Temp_Dir)
  
        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "VDiskCreate", " VDiskCreate Files Have Been Analyzed " )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                

    def Create_Diskpart_Script(self, size_of_disk, vdisk_name):
        # get the directory to store the scripts used by diskpart
        for x in range(68, 90):
            try:
                if not os.path.exists(chr(x) + ":"):
                   pass
            except:
                open_drive = chr(x) + ":"
                break
            
        #open_drives = [ chr(x) + ": " for x in range(68,90) if not os.path.exists(chr(x) + ":") ]
        vdisk_script_dir = os.path.join(Case.getCurrentCase().getTempDirectory(), "vdisk_scripts")
        try:
            os.mkdir(vdisk_script_dir)
        except:
            self.log(Level.INFO, "Vdisk script directory already exists")

        # script names
        vdisk_create_script = os.path.join(vdisk_script_dir, "create_vdisk.txt")
        vdisk_unmount_script = os.path.join(vdisk_script_dir, "unmount_vdisk.txt")
        vdisk_mount_script = os.path.join(vdisk_script_dir, "mount_vdisk.txt")

        # Create create, mount and format script
        vdc = open(vdisk_create_script, "w")
        vdc.write('create vdisk file="' + vdisk_name + '" maximum=' + str(size_of_disk) + " type=expandable \n")
        vdc.write("attach vdisk \n")
        vdc.write("create partition primary \n")
        vdc.write('format fs=ntfs label="Preview" quick \n')
        vdc.write("assign letter=" + open_drive + " \n")
        vdc.close()

        # Create Mount script
        vdc = open(vdisk_mount_script, "w")
        vdc.write('select vdisk file="' + vdisk_name + '"\n')
        vdc.write("attach vdisk \n")
        vdc.close()

        # Create Unmount script
        vdc = open(vdisk_unmount_script, "w")
        vdc.write('select vdisk file="' + vdisk_name + '"\n')
        vdc.write("detach vdisk \n")
        vdc.close()
        return vdisk_create_script, vdisk_unmount_script, vdisk_mount_script, open_drive