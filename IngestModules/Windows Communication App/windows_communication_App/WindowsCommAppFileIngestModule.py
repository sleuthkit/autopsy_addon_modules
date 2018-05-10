# This module was an attempt to solve a UCD assignment with the intend
# to teach practical use of Autopsy 
# 
# Contact: Tom Van der Mussele [tomvandermussele <at> gmail [dot] com]
#
# 
#https://github.com/sleuthkit/autopsy/blob/3bb09d8b6457b4116f70068bd7ea240bd7be1f1f/Core/src/org/sleuthkit/autopsy/modules/hashdatabase/HashDbIngestModule.java
#import org.sleuthkit.datamodel.HashHitInfo;
#import org.sleuthkit.datamodel.HashUtility;
#if (md5Hash == null || md5Hash.isEmpty()) {
#md5Hash = HashUtility.calculateMd5(file);

import jarray
import os
import xml.etree.ElementTree as ET
import inspect
from java.io import File
from java.lang import System
from java.util.logging import Level
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.datamodel import HashUtility 
from org.sleuthkit.datamodel import HashHitInfo
import xml.etree.ElementTree as ET
from org.sleuthkit.autopsy.datamodel import ContentUtils


# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the anlaysis.
# TODO: Rename this to something more specific.  Search and replace for it because it is used a few times


         
class WindowsCommunicationModuleFactory(IngestModuleFactoryAdapter):

    # TODO: give it a unique name.  Will be shown in module list, logs, etc.
    moduleName = "Windows Communication App - Contacts"

    def getModuleDisplayName(self):
        return self.moduleName

    # TODO: Give it a description
    def getModuleDescription(self):
        return "Windows Communication CONTACTS."

    def getModuleVersionNumber(self):
        return "1.0"

    # Return true if module wants to get called for each file
    def isDataSourceIngestModuleFactory(self):
        return True

    # can return null if isFileIngestModuleFactory returns false
    def createDataSourceIngestModule(self, ingestOptions):
        return WindowsCommunicationModule()


class WindowsCommunicationModule(DataSourceIngestModule):
    
    _logger = Logger.getLogger(WindowsCommunicationModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self):
        self.context = None


    def startUp(self, context):
        self.context = context
       
        pass
    # Where the analysis is done.  Each file will be passed into here.
    # The 'file' object being passed in is of type org.sleuthkit.datamodel.AbstractFile.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/classorg_1_1sleuthkit_1_1datamodel_1_1_abstract_file.html
    # TODO: Add your analysis code in here.
    def process(self, datasource, progressbar):
    
    
        PostBoard=IngestServices.getInstance()
        progressbar.switchToIndeterminate()
        ccase = Case.getCurrentCase().getSleuthkitCase()
        blackboard = Case.getCurrentCase().getServices().getBlackboard()
        msgcounter = 0
        # if ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) or 
            # (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) or 
            # (file.isFile() == true)):
            # return IngestModule.ProcessResult.OK
        #
        
        #prepare artifacts
   
        artifact_name = "TSK_WINCOM_CONTACT"
        artifact_desc = "Windows Communication Contacts"
        
        try:
            
            artID_wincom_contact = ccase.addArtifactType(artifact_name, artifact_desc)
            
            attribute_name = "TSK_WINCOM_CONTACT_SERVICE"
            attribute_name1 = "TSK_WINCOM_CONTACT_APPID"
            attribute_name2 = "TSK_WINCOM_CONTACT_FIRSTNAME"
            attribute_name3 = "TSK_WINCOM_CONTACT_LASTNAME"
            attribute_name4 = "TSK_WINCOM_CONTACT_COUNTRY"
            attribute_name5 = "TSK_WINCOM_CONTACT_LOCALITY"
            attribute_name6 = "TSK_WINCOM_CONTACT_REGION"
            attribute_name7 = "TSK_WINCOM_CONTACT_BIRTHDAY"
            
            attID_ex= ccase.addArtifactAttributeType(attribute_name, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Service vs Person")
            attID_ex1 = ccase.addArtifactAttributeType(attribute_name1, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Application")
            attID_ex2 = ccase.addArtifactAttributeType(attribute_name2, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "First Name")
            attID_ex3 = ccase.addArtifactAttributeType(attribute_name3, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Last Name")
            attID_ex4 = ccase.addArtifactAttributeType(attribute_name4, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Country")
            attID_ex5 = ccase.addArtifactAttributeType(attribute_name5, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "City")
            attID_ex6 = ccase.addArtifactAttributeType(attribute_name6, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Region")
            attID_ex7 = ccase.addArtifactAttributeType(attribute_name7, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Birthday")
            
        except:
            message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA, WindowsCommunicationModuleFactory.moduleName + str(msgcounter), "Error creating artifacts"+ str(msgcounter))
            #IngestServices.getInstance().postMessage(message)
            self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")
            
        artID_wincom_contact = ccase.getArtifactTypeID(artifact_name)
        artID_wincom_contact_evt = ccase.getArtifactType(artifact_name)
        #get files
        
        
        ##IngestServices.getInstance().postMessage(message)
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(datasource, "%appcontent-ms")
        numFiles = len(files)
        progressbar.switchToDeterminate(numFiles)
        fileCount = 0
        
        
        for file in files:
            fileCount = fileCount + 1
            progressbar.progress(fileCount)
            progressbar.progress("Windows Communication Analyzer")
            msgcounter+=1
            # message = IngestMessage.createMessage(
            # IngestMessage.MessageType.DATA, WindowsCommunicationModuleFactory.moduleName + str(msgcounter), str(msgcounter) + " - in file loop and found file:" + str(file.getParentPath()))
            # #IngestServices.getInstance().postMessage(message)
            ParentPath = file.getParentPath()
            
            #if "microsoft.windowscommunicationsapps"  in ParentPath and "_8wekyb3d8bbwe" in ParentPath and file.getName().lower().endswith("appcontent-ms") and "Address" in ParentPath :
            if file.getSize() > 0 and "microsoft.windowscommunicationsapps"  in ParentPath:
                lclXMLPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".appcontent-ms")
                ContentUtils.writeToFile(file, File(lclXMLPath))
                
                if self.context.isJobCancelled():
                    return IngestModule.ProcessResult.OK

                with open(lclXMLPath, "rb") as XMLFile:
                    with open(lclXMLPath+".rewrite", 'w+b') as NewXMLFile:
                        contents = XMLFile.read()
                        newContent = contents.decode('utf-16').encode('utf-8')
                        NewXMLFile.write(newContent.replace('<?xml version="1.0" encoding="utf-16"?>','<?xml version="1.0" encoding="utf-8"?>'))
                        NewXMLFile.close()
                XMLFile.close()
                f = open(lclXMLPath+".rewrite", "rb")
                
                all = f.read()
                f.close()
                message = IngestMessage.createMessage(
                IngestMessage.MessageType.DATA, WindowsCommunicationModuleFactory.moduleName + str(msgcounter), all)
                #IngestServices.getInstance().postMessage(message)
                #XMLFile = open(lclXMLPath, "rb")
                AppID="**"
                FirstName = "**"
                LastName = "**"
                HomeAddress1Country = "**"
                HomeAddress1Locality = "**"
                HomeAddress1Region = "**"
                Birthday = "**"
                Service = "**"
                root = ET.fromstring(all)
                
                for elem in root.iter():
                   
                    teller = 0
                    if "System.Contact.ConnectedServiceName" in str(elem.attrib):
                        if len(elem.text) == 2:
                            for child in elem:
                                teller =+1
                                Service = child.text
#                                if teller == 1:
                                break
                        else:

                            Service = elem.text
                    
                    
                    elif "System.AppUserModel.PackageRelativeApplicationID" in  str(elem.attrib):
                        
                        if len(elem.text) == 2:
                            
                            for child in elem:
                                teller =+1
                                AppID = child.text
#                                if teller == 1:
                                break
                        else:
                            if len(elem.text)==0:
                                AppID = elem.text
                            else:
                                AppID = "**"
                        
                    elif "System.Contact.FirstName" in str(elem.attrib):

                        if len(elem.text) == 2:
                            for child in elem:
                                teller =+1
                                FirstName = child.text
                                if teller == 1:
                                    break
                        else:
                            FirstName = elem.text
                    elif "System.Contact.LastName" in str(elem.attrib):
                        
                        if len(elem.text) == 2:
                            for child in elem:
                                teller =+1
                                LastName = child.text
                                if teller == 1:
                                    break
                        else:
                            LastName = elem.text
                    elif "System.Contact.HomeAddress1Country" in str(elem.attrib):
                        
                        if len(elem.text) == 2:
                            teller =+1
                            for child in elem:
                                HomeAddress1Country = child.text
                                if teller == 1:
                                    break
                        else:
                            HomeAddress1Country = elem.text
                    elif "System.Contact.HomeAddress1Locality" in str(elem.attrib):

                        if len(elem.text) == 2:
                            for child in elem:
                                teller =+1
                                HomeAddress1Locality = child.text
                                if teller == 1:
                                    break
                        else:
                            HomeAddress1Locality = elem.text
                    elif "System.Contact.HomeAddress1Region" in str(elem.attrib):
                        
                        if len(elem.text) == 2:
                            for child in elem:
                                teller =+1
                                HomeAddress1Region = child.text
                                if teller == 1:
                                    break
                        else:
                            HomeAddress1Region = elem.text
                    elif "System.Contact.Birthday" in str(elem.attrib):
                        
                        if len(elem.text) == 2:
                            for child in elem:
                                teller =+1
                                Birthday = child.text
                                if teller == 1:
                                    break
                        else:
                            Birthday = elem.text
                    else:
                        #another value - manual forensics
                        #AppID = "BLAHELSE"
                        pass
                
                
                #IngestServices.getInstance().postMessage(message)
                #end looping through elements
                
              
                #ready for next file
                art = file.newArtifact(artID_wincom_contact)
                attID_ex =ccase.getAttributeType("TSK_WINCOM_CONTACT_SERVICE")
                art.addAttribute(BlackboardAttribute(attID_ex, WindowsCommunicationModuleFactory.moduleName, Service))
                attID_ex1 =ccase.getAttributeType("TSK_WINCOM_CONTACT_APPID")
                art.addAttribute(BlackboardAttribute(attID_ex1, WindowsCommunicationModuleFactory.moduleName, AppID))
                attID_ex2 =ccase.getAttributeType("TSK_WINCOM_CONTACT_FIRSTNAME")
                art.addAttribute(BlackboardAttribute(attID_ex2, WindowsCommunicationModuleFactory.moduleName, FirstName))
                attID_ex3 =ccase.getAttributeType("TSK_WINCOM_CONTACT_LASTNAME")
                art.addAttribute(BlackboardAttribute(attID_ex3, WindowsCommunicationModuleFactory.moduleName, LastName))
                attID_ex4 =ccase.getAttributeType("TSK_WINCOM_CONTACT_COUNTRY")
                art.addAttribute(BlackboardAttribute(attID_ex4, WindowsCommunicationModuleFactory.moduleName, HomeAddress1Country))
                attID_ex5 =ccase.getAttributeType("TSK_WINCOM_CONTACT_LOCALITY")
                art.addAttribute(BlackboardAttribute(attID_ex5, WindowsCommunicationModuleFactory.moduleName, HomeAddress1Locality))
                attID_ex6 =ccase.getAttributeType("TSK_WINCOM_CONTACT_REGION")
                art.addAttribute(BlackboardAttribute(attID_ex6, WindowsCommunicationModuleFactory.moduleName, HomeAddress1Region))
                attID_ex7 =ccase.getAttributeType("TSK_WINCOM_CONTACT_BIRTHDAY")
                art.addAttribute(BlackboardAttribute(attID_ex7, WindowsCommunicationModuleFactory.moduleName, Birthday))
                IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(WindowsCommunicationModuleFactory.moduleName, artID_wincom_contact_evt, None))
            else:
                pass
        
        #cleanup
        os.remove(lclXMLPath)
        os.remove(lclXMLPath+".rewrite")
        return IngestModule.ProcessResult.OK
            
    # def shutDown(self):
        # # As a final part of this example, we'll send a message to the ingest inbox with the number of files found (in this thread)
        # msg2 = IngestMessage.createMessage(
        # IngestMessage.MessageType.DATA, WindowsCommunicationModuleFactory.moduleName, 
                # "Found " + str(self.filesFound))
        # ingestServices = IngestServices.getInstance().postMessage(msg2)
        