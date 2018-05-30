# This python autopsy module will Check the status of a Cuckoo server and
# submit files to it.
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

# Cuckoo.
# April 2017
# 
# Comments 
#   Version 1.0 - Initial version - April 2017
# 

import jarray
import inspect
import os
from subprocess import Popen, PIPE

from javax.swing import JCheckBox
from javax.swing import JButton
from javax.swing import ButtonGroup
from javax.swing import JTextField
from javax.swing import JLabel
from java.awt import GridLayout
from java.awt import GridBagLayout
from java.awt import GridBagConstraints
from javax.swing import JPanel
from javax.swing import JList
from javax.swing import JScrollPane
from javax.swing import JFileChooser
from javax.swing import JComboBox
from javax.swing.filechooser import FileNameExtensionFilter

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
class CuckooIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Cuckoo Module"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Send Files to Cuckoo"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def getDefaultIngestJobSettings(self):
        return CuckooSettingsWithUISettings()

    def hasIngestJobSettingsPanel(self):
        return True

    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, CuckooSettingsWithUISettings):
            raise IllegalArgumentException("Expected settings argument to be instanceof SampleIngestModuleSettings")
        self.settings = settings
        return CuckooSettingsWithUISettingsPanel(self.settings)

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return CuckooIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class CuckooIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(CuckooIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self.Submit_File = self.local_settings.getSubmit_File()
        self.Submit_URL = self.local_settings.getSubmit_URL()
        self.Protocol = self.local_settings.getProtocol()
        self.IP_Address = self.local_settings.getIP_Address()
        self.Port_Number = self.local_settings.getPort_Number()
        self.tag_list = self.local_settings.gettag_list()

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context

        #Show parameters that are passed in
        self.log(Level.INFO, "Submit File  =====>" + str(self.Submit_File))
        self.log(Level.INFO, "Submit URL  =====>" + str(self.Submit_URL))
        self.log(Level.INFO, "Protocol  =====>" + str(self.Protocol))
        self.log(Level.INFO, "IP Address  =====>" + str(self.IP_Address))
        self.log(Level.INFO, "Port_Number  =====>" + str(self.Port_Number))
        self.log(Level.INFO, "Tags  =====>" + str(self.tag_list))
        
        # Check to see if the file to execute exists, if it does not then raise an exception and log error
        # data is taken from the UI
        self.path_to_cuckoo_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cuckoo_api.exe")
        if not os.path.exists(self.path_to_cuckoo_exe):
            raise IngestModuleException("cuckoo_api.exe was not found in module folder")
        
        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException(IngestModule(), "Oh No!")
        pass

    # Where the analysis is done.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # See:x http://www.sleuthkit.org/sleuthkit/docs/jni-docs/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html
    def process(self, dataSource, progressBar):

        self.log(Level.INFO, "Starting to process, Just before call to parse_safari_history")

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
        
		# Create Event Log directory in temp directory, if it exists then continue on processing		
        Temp_Dir = Case.getCurrentCase().getTempDirectory()
        self.log(Level.INFO, "create Directory " + Temp_Dir)
        
        Files_submitted = 0
        
        try:
		    os.mkdir(Temp_Dir + "\Cuckoo")
        except:
		    self.log(Level.INFO, "Cuckoo Directory already exists " + Temp_Dir)
			
        for tag_name in self.tag_list:
            self.log(Level.INFO, "Processing Tag ==> " + tag_name)
            
            sql_statement = "select name, parent_path from tsk_files a, tag_names c, content_tags d " + \
                        " where d.tag_name_id = c.tag_name_id and c.display_name = '" + tag_name + "' and d.obj_id = a.obj_id;"
            self.log(Level.INFO, "SQL Statement ==> " + sql_statement)
            skCase = Case.getCurrentCase().getSleuthkitCase()
            dbquery = skCase.executeQuery(sql_statement)
            resultSet = dbquery.getResultSet()
            while resultSet.next():
                 fileManager = Case.getCurrentCase().getServices().getFileManager()
                 files = fileManager.findFiles(dataSource, resultSet.getString("name"), resultSet.getString("parent_path"))
                 numFiles = len(files)
                 for file in files:
                    
                    # Check if the user pressed cancel while we were busy
                    if self.context.isJobCancelled():
                        return IngestModule.ProcessResult.OK

                    #self.log(Level.INFO, "Processing file: " + file.getName())

                    # Save the File locally in the temp folder. 
                    FilePath = os.path.join(Temp_Dir + "\cuckoo", file.getName())
                    ContentUtils.writeToFile(file, File(FilePath))
                    
                    # Call the Cuckoo API to submit the file
                    pipe = Popen([self.path_to_cuckoo_exe, self.Protocol,self.IP_Address, self.Port_Number, "submit_file", FilePath ], stdout=PIPE, stderr=PIPE)
                    
                    out_text = pipe.communicate()[0]
                    self.log(Level.INFO, resultSet.getString("parent_path") + "\\" + resultSet.getString("name") + "<== Status of File Submit is " + out_text + " ==>")
                    
                    Files_submitted = Files_submitted + 1
                    
                    #Submit error Message for 
                    message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                            "Cuckoo File Submit",  resultSet.getString("parent_path") + "/" + resultSet.getString("name") + " " + out_text )
                    IngestServices.getInstance().postMessage(message)
        
                    #Delete File that was written
                    try:
                       os.remove(FilePath)
                    except:
                       self.log(Level.INFO, "removal of " + FilePath + " Failed ")
            
            dbquery.close()

        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                "Cuckoo File Submit",  str(Files_submitted) + " files have been submitted to cuckoo" )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                
		

# Stores the settings that can be changed for each ingest job
# All fields in here must be serializable.  It will be written to disk.
# TODO: Rename this class
class CuckooSettingsWithUISettings(IngestModuleIngestJobSettings):
    serialVersionUID = 1L

    def __init__(self):
        self.Cuckoo_Dir_Found = False
        self.Port_Number = ""
        self.Protocol = ""
        self.IP_Address = ""
        self.ComboBox = ""
        self.tag_list = []
        self.Submit_File = False
        self.Submit_URL = False

        
    def getVersionNumber(self):
        return serialVersionUID

    # Define getters and settings for data you want to store from UI
    def getPort_Number(self):
        return self.Port_Number

    def setPort_Number(self, flag):
        self.Port_Number = flag

    def getProtocol(self):
        return self.Protocol

    def setProtocol(self, flag):
        self.Protocol = flag
        
    def getIP_Address(self):
        return self.IP_Address

    def setIP_Address(self, flag):
        self.IP_Address = flag
        
    def getSubmit_File(self):
        return self.Submit_File

    def setSubmit_File(self, flag):
        self.Submit_File = flag
        
    def getSubmit_URL(self):
        return self.Submit_URL

    def setSubmit_URL(self, flag):
        self.Submit_URL = flag
        
    def getComboBox(self):
        return self.ComboBox

    def setComboBox(self, entry):
        self.ComboBox = entry

    def gettag_list(self):
        return self.tag_list

    def cleartag_list(self):
        self.tag_list[:] = []

    def settag_list(self, entry):
        self.tag_list = entry
    
# UI that is shown to user for each ingest job so they can configure the job.
# TODO: Rename this
class CuckooSettingsWithUISettingsPanel(IngestModuleIngestJobSettingsPanel):
    # Note, we can't use a self.settings instance variable.
    # Rather, self.local_settings is used.
    # https://wiki.python.org/jython/UserGuide#javabean-properties
    # Jython Introspector generates a property - 'settings' on the basis
    # of getSettings() defined in this class. Since only getter function
    # is present, it creates a read-only 'settings' property. This auto-
    # generated read-only property overshadows the instance-variable -
    # 'settings'
    
    # We get passed in a previous version of the settings so that we can
    # prepopulate the UI
    # TODO: Update this for your UI
    def __init__(self, settings):
        self.local_settings = settings
        self.tag_list = []
        self.initComponents()
        self.customizeComponents()
        self.path_to_cuckoo_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cuckoo_api.exe")
 
    # Check the checkboxs to see what actions need to be taken
    def checkBoxEvent(self, event):
        if self.Submit_File_CB.isSelected():
            self.local_settings.setSubmit_File(True)
            self.local_settings.setSubmit_URL(False)
        else:
            self.local_settings.setSubmit_File(False)
            
        # if self.Submit_URL_CB.isSelected():
            # self.local_settings.setSubmit_URL(True)
            # self.local_settings.setSubmit_File(False)
        # else:
            # self.local_settings.setSubmit_URL(False)
            
    def onchange_lb(self, event):
        self.local_settings.cleartag_list()
        list_selected = self.List_Box_LB.getSelectedValuesList()
        self.local_settings.settag_list(list_selected)      

    def find_tags(self):
        
        sql_statement = "SELECT distinct(display_name) u_tag_name FROM content_tags INNER JOIN tag_names ON " + \
                        " content_tags.tag_name_id = tag_names.tag_name_id;"
        skCase = Case.getCurrentCase().getSleuthkitCase()
        dbquery = skCase.executeQuery(sql_statement)
        resultSet = dbquery.getResultSet()
        while resultSet.next():
             self.tag_list.append(resultSet.getString("u_tag_name"))
        dbquery.close()

    # Check to see if there are any entries that need to be populated from the database.        
    def check_Database_entries(self):
        head, tail = os.path.split(os.path.abspath(__file__)) 
        settings_db = head + "\\gui_Settings.db3"
        try: 
            Class.forName("org.sqlite.JDBC").newInstance()
            dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % settings_db)
        except SQLException as e:
            self.Error_Message.setText("Error Opening Settings DB!")
 
        try:
           stmt = dbConn.createStatement()
           SQL_Statement = 'Select Protocol, cuckoo_host, cuckoo_port from cuckoo_server' 
           resultSet = stmt.executeQuery(SQL_Statement)
           while resultSet.next():
               self.Protocol_TF.setText(resultSet.getString("Protocol"))
               self.IP_Address_TF.setText(resultSet.getString("cuckoo_host"))
               self.Port_Number_TF.setText(resultSet.getString("cuckoo_port"))
               self.local_settings.setProtocol(resultSet.getString("Protocol"))
               self.local_settings.setIP_Address(resultSet.getString("cuckoo_host"))
               self.local_settings.setPort_Number(resultSet.getString("cuckoo_port"))
           self.Error_Message.setText("Settings Read successfully!")
        except SQLException as e:
            self.Error_Message.setText("Error Reading Settings Database")

        stmt.close()
        dbConn.close()

    # Save entries from the GUI to the database.
    def SaveSettings(self, e):
        
        head, tail = os.path.split(os.path.abspath(__file__)) 
        settings_db = head + "\\GUI_Settings.db3"
        try: 
            Class.forName("org.sqlite.JDBC").newInstance()
            dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % settings_db)
        except SQLException as e:
            self.Error_Message.setText("Error Opening Settings")
 
        try:
           stmt = dbConn.createStatement()
           SQL_Statement = ""
           SQL_Statement = 'Update cuckoo_server set Protocol = "' + self.Protocol_TF.getText() + '", ' + \
                               '                     Cuckoo_Host = "' + self.IP_Address_TF.getText() + '", ' + \
                               '                     Cuckoo_port = "' + self.Port_Number_TF.getText() + '";' 
           
           #self.Error_Message.setText(SQL_Statement)
           stmt.execute(SQL_Statement)
           self.Error_Message.setText("Cuckoo settings Saved")
           #self.local_settings.setCuckoo_Directory(self.Program_Executable_TF.getText())
        except SQLException as e:
           self.Error_Message.setText(e.getMessage())
        stmt.close()
        dbConn.close()
           
    # Check to see if the Cuckoo server is available and you can talk to it
    def Check_Server(self, e):

       pipe = Popen([self.path_to_cuckoo_exe, self.Protocol_TF.getText(),self.IP_Address_TF.getText(), self.Port_Number_TF.getText(), "cuckoo_status" ], stdout=PIPE, stderr=PIPE)
        
       out_text = pipe.communicate()[0]
       self.Error_Message.setText("Cuckoo Status is " + out_text)
       #self.log(Level.INFO, "Cuckoo Status is ==> " + out_text)

           
    # def onchange_cb(self, event):
        # self.local_settings.setComboBox(event.item) 

    # Create the initial data fields/layout in the UI
    def initComponents(self):
        self.panel0 = JPanel()

        self.rbgPanel0 = ButtonGroup() 
        self.gbPanel0 = GridBagLayout() 
        self.gbcPanel0 = GridBagConstraints() 
        self.panel0.setLayout( self.gbPanel0 ) 

        self.Label_1 = JLabel("Protocol:")
        self.Label_1.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 1 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Label_1, self.gbcPanel0 ) 
        self.panel0.add( self.Label_1 ) 

        self.Protocol_TF = JTextField(20) 
        self.Protocol_TF.setEnabled(True)
        self.gbcPanel0.gridx = 4 
        self.gbcPanel0.gridy = 1 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Protocol_TF, self.gbcPanel0 ) 
        self.panel0.add( self.Protocol_TF ) 

        self.Blank_1 = JLabel( " ") 
        self.Blank_1.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 3
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Blank_1, self.gbcPanel0 ) 
        self.panel0.add( self.Blank_1 ) 

        self.Label_2 = JLabel("Cuckoo IP Address")
        self.Label_2.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 5 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Label_2, self.gbcPanel0 ) 
        self.panel0.add( self.Label_2 ) 

        self.IP_Address_TF = JTextField(20) 
        self.IP_Address_TF.setEnabled(True)
        self.gbcPanel0.gridx = 4 
        self.gbcPanel0.gridy = 5 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.IP_Address_TF, self.gbcPanel0 ) 
        self.panel0.add( self.IP_Address_TF ) 

        self.Blank_2 = JLabel( " ") 
        self.Blank_2.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 7
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Blank_2, self.gbcPanel0 ) 
        self.panel0.add( self.Blank_2 ) 

        self.Label_3 = JLabel("Port Number")
        self.Label_3.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 9 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Label_3, self.gbcPanel0 ) 
        self.panel0.add( self.Label_3 ) 

        self.Port_Number_TF = JTextField(20) 
        self.Port_Number_TF.setEnabled(True)
        self.gbcPanel0.gridx = 4 
        self.gbcPanel0.gridy = 9 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Port_Number_TF, self.gbcPanel0 ) 
        self.panel0.add( self.Port_Number_TF ) 

        self.Blank_3 = JLabel( " ") 
        self.Blank_3.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 11
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Blank_3, self.gbcPanel0 ) 
        self.panel0.add( self.Blank_3 ) 

        
        self.Save_Settings_BTN = JButton( "Save Setup", actionPerformed=self.SaveSettings) 
        self.Save_Settings_BTN.setEnabled(True)
        self.rbgPanel0.add( self.Save_Settings_BTN ) 
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 13
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Save_Settings_BTN, self.gbcPanel0 ) 
        self.panel0.add( self.Save_Settings_BTN ) 

        self.Blank_4 = JLabel( " ") 
        self.Blank_4.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 15
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Blank_4, self.gbcPanel0 ) 
        self.panel0.add( self.Blank_4 ) 

        self.Blank_5 = JLabel( "Tag to Choose: ") 
        self.Blank_5.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 17
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Blank_5, self.gbcPanel0 ) 
        self.panel0.add( self.Blank_5 ) 

        self.find_tags()
        self.List_Box_LB = JList( self.tag_list, valueChanged=self.onchange_lb)
        self.List_Box_LB.setVisibleRowCount( 3 ) 
        self.scpList_Box_LB = JScrollPane( self.List_Box_LB ) 
        self.gbcPanel0.gridx = 4 
        self.gbcPanel0.gridy = 17 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 1 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.scpList_Box_LB, self.gbcPanel0 ) 
        self.panel0.add( self.scpList_Box_LB ) 

        self.Blank_6 = JLabel( " ") 
        self.Blank_6.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 19
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Blank_6, self.gbcPanel0 ) 
        self.panel0.add( self.Blank_6 ) 

        self.Submit_File_CB = JCheckBox("Submit a File", actionPerformed=self.checkBoxEvent)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 21 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Submit_File_CB, self.gbcPanel0 ) 
        self.panel0.add( self.Submit_File_CB ) 

        # self.Submit_URL_CB = JCheckBox("Submit a URL", actionPerformed=self.checkBoxEvent)
        # self.gbcPanel0.gridx = 2 
        # self.gbcPanel0.gridy = 23 
        # self.gbcPanel0.gridwidth = 1 
        # self.gbcPanel0.gridheight = 1 
        # self.gbcPanel0.fill = GridBagConstraints.BOTH 
        # self.gbcPanel0.weightx = 1 
        # self.gbcPanel0.weighty = 0 
        # self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        # self.gbPanel0.setConstraints( self.Submit_URL_CB, self.gbcPanel0 ) 
        # self.panel0.add( self.Submit_URL_CB ) 

        self.Check_Server_Status_BTN = JButton( "Check Server Status", actionPerformed=self.Check_Server) 
        self.Check_Server_Status_BTN.setEnabled(True)
        self.rbgPanel0.add( self.Save_Settings_BTN ) 
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 25
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Check_Server_Status_BTN, self.gbcPanel0 ) 
        self.panel0.add( self.Check_Server_Status_BTN ) 

        self.Error_Message = JLabel( "") 
        self.Error_Message.setEnabled(True)
        self.gbcPanel0.gridx = 2
        self.gbcPanel0.gridy = 27
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH
        self.gbPanel0.setConstraints( self.Error_Message, self.gbcPanel0 ) 
        self.panel0.add( self.Error_Message ) 


        self.add(self.panel0)

    # Custom load any data field and initialize the values
    def customizeComponents(self):
        #self.Exclude_File_Sources_CB.setSelected(self.local_settings.getExclude_File_Sources())
        #self.Run_Cuckoo_CB.setSelected(self.local_settings.getRun_Cuckoo())
        #self.Import_Cuckoo_CB.setSelected(self.local_settings.getImport_Cuckoo())
        self.check_Database_entries()

    # Return the settings used
    def getSettings(self):
        return self.local_settings
