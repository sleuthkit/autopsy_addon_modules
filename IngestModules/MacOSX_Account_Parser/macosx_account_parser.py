"""
Copyright 2020 Luke Gaddie

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

import os
import inspect
from biplist import readPlist, NotBinaryPlistException, InvalidPlistException
from StringIO import StringIO

from java.io import File
from java.util.logging import Level
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Blackboard
from org.sleuthkit.autopsy.datamodel import ContentUtils


class OSXAccountParserDataSourceIngestModuleFactory(IngestModuleFactoryAdapter):
    moduleName = "MacOSX Account Parser"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Extract user account information and account shadows from OSX v10.8+ for hashcat cracking."

    def getModuleVersionNumber(self):
        return "1.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return OSXAccountParserDataSourceIngestModule()


class OSXAccountParserDataSourceIngestModule(DataSourceIngestModule):
    _logger = Logger.getLogger(OSXAccountParserDataSourceIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self):
        self.context = None

        self.osAccountAttributeTypes = {
            'home': {
                'attr_key': 'TSK_HOME_DIRECTORY',
                'attr_type': BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                'display_name': 'Home Directory',
                'custom': True,
            },
            'shell': {
                'attr_key': 'TSK_SHELL',
                'attr_type': BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                'display_name': 'Shell',
                'custom': True,
            },
            'hint': {
                'attr_key': 'TSK_PASSWORD_HINT',
                'attr_type': BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                'display_name': 'Password Hint',
                'custom': True,
            },
            'failedLoginTimestamp': {
                'attr_key': 'TSK_FAILED_LOGIN_TIMESTAMP',
                'attr_type': BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME,
                'display_name': 'Last Failed Login',
                'custom': True,
            },
            'failedLoginCount': {
                'attr_key': 'TSK_FAILED_LOGIN_COUNT',
                'attr_type': BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG,
                'display_name': 'Failed Login Count',
                'custom': True,
            },
            'passwordLastSetTime': {
                'attr_key': 'TSK_PASSWORD_LAST_SET_TIME',
                'attr_type': BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME,
                'display_name': 'Password Last Set',
                'custom': True,
            },
            'generateduuid': {
                'attr_key': 'TSK_GENERATED_UUID',
                'attr_type': BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                'display_name': 'Generated UUID',
                'custom': True,
            },
            'IsHidden': {
                'attr_key': 'TSK_IS_HIDDEN',
                'attr_type': BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                'display_name': 'Hidden',
                'custom': True,
            },
            'creationTime': {
                'attr_key': 'TSK_DATETIME_CREATED',
            },
            'realname': {
                'attr_key': 'TSK_NAME',
            },
            'uid': {
                'attr_key': 'TSK_USER_ID',
            },
            'name': {
                'attr_key': 'TSK_USER_NAME',
            },
        }

        self.hashedCredentialAttributeTypes = {
            'hashType': {
                'attr_key': 'TSK_HASH_TYPE',
                'attr_type': BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                'display_name': 'Hash Type',
                'custom': True,
            },
            'salt': {
                'attr_key': 'TSK_SALT',
                'attr_type': BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                'display_name': 'Salt',
                'custom': True,
            },
            'iterations': {
                'attr_key': 'TSK_ITERATIONS',
                'attr_type': BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG,
                'display_name': 'Iterations',
                'custom': True,
            },
            'entropy': {
                'attr_key': 'TSK_HASH_ENTROPY',
                'attr_type': BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                'display_name': 'Entropy',
                'custom': True,
            },
            'verifier': {
                'attr_key': 'TSK_VERIFIER',
                'attr_type': BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                'display_name': 'Verifier',
                'custom': True,
            },
            'hashcatEntry': {
                'attr_key': 'TSK_HASHCAT_ENTRY',
                'attr_type': BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                'display_name': 'Hashcat Entry',
                'custom': True,
            },

        }

        self.moduleName = "MacOSX Account Parser"
        self.temporary_dir = os.path.join(Case.getCurrentCase().getTempDirectory(), self.moduleName.replace(' ', '_'))

        self.case = Case.getCurrentCase().getSleuthkitCase()
        self.file_manager = Case.getCurrentCase().getServices().getFileManager()
        self.blackboard = Case.getCurrentCase().getSleuthkitCase().getBlackboard()

    def startUp(self, context):
        self.context = context

    def process(self, dataSource, progressBar):

        try:
            os.mkdir(self.temporary_dir)
        except:
            pass

        progressBar.switchToIndeterminate()

        self.setup_custom_artifact_types()
        self.setup_custom_attribute_types()

        filesProcessed = 0

        files = self.file_manager.findFiles(dataSource, "%.plist", "%var/db/dslocal/nodes/Default/users/")

        totalNumberFiles = len(files)
        progressBar.switchToDeterminate(totalNumberFiles)

        self.log(Level.INFO, "Found " + str(totalNumberFiles) + " files to process.")
        for file in files:
            self.log(Level.INFO, "Processing %s" % file.getName())

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            # Copy the Plist file to a temporary directory to work with
            tmpPlistFile = self.copy_to_temp_directory(file)
            self.log(Level.INFO, "Reading %s as a plist" % tmpPlistFile)

            try:
                # Read the Plist file using biplist
                plist = readPlist(tmpPlistFile)

                # Extract all of the plist data that we can
                extractedData = self.extract_plist_data(plist)

                # Each Plist file gets a generic TSK_OS_ACCOUNT Artifact Type
                osAccountArtifact = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_OS_ACCOUNT)
                osArtifactAttributes = []

                # We can iterate over any expected attribute types and assign them to the artifact.
                for dictKey in self.osAccountAttributeTypes:
                    try:
                        osArtifactAttributes.append(BlackboardAttribute(
                            self.case.getAttributeType(self.osAccountAttributeTypes[dictKey]['attr_key']),
                            self.moduleName, extractedData[dictKey]))
                    except KeyError:
                        # Discarding the attribute type if, for whatever reason, they're not in the Plist.
                        pass

                # When we're done, go ahead and add them to the OS Account Artifact. We'll post it later.
                osAccountArtifact.addAttributes(osArtifactAttributes)

                # An account shadow can have multiple hashes (e.g. SALTED-SHA512-PBKDF2 & SRP-RFC5054-4096-SHA512-PBKDF2)
                # so we'll create an array to handle them all, then add them all at the end.
                hashedCredArtifacts = []

                # For each extracted hash
                for shadow in extractedData['shadows']:
                    # Create a new artifact using our custom TSK_HASHED_CREDENTIAL artifact type we set up earlier.
                    hashedCredArtifact = file.newArtifact(self.case.getArtifactTypeID("TSK_HASHED_CREDENTIAL"))

                    hashedCredArtifactAttributes = []
                    # We can iterate over any expected attribute types and assign them to the artifact.
                    for dictKey in self.hashedCredentialAttributeTypes:
                        try:
                            hashedCredArtifactAttributes.append(BlackboardAttribute(
                                self.case.getAttributeType(
                                    self.hashedCredentialAttributeTypes[dictKey]['attr_key']),
                                self.moduleName, shadow[dictKey]
                            ))
                        except KeyError:
                            # Discarding the attribute type if, for whatever reason, they're not in the Plist.
                            pass

                        # Add the attributes to the artifact.
                        hashedCredArtifact.addAttributes(hashedCredArtifactAttributes)
                    # and add our artifact to the array of found shadows for the account.
                    hashedCredArtifacts.append(hashedCredArtifact)

                try:
                    # Post our extracted account information.
                    self.blackboard.postArtifact(osAccountArtifact, self.moduleName)

                    # Then iterate over our harvested credential hashes for the account, posting them.
                    for hashedCredArtifact in hashedCredArtifacts:
                        self.blackboard.postArtifact(hashedCredArtifact, self.moduleName)

                except Blackboard.BlackboardException:
                    self.log(Level.SEVERE,
                             "Unable to index blackboard artifact " + str(osAccountArtifact.getArtifactTypeName()))

            except (InvalidPlistException, NotBinaryPlistException), e:
                self.log(Level.INFO, "Unable to parse %s as a Plist file. Skipping." % file.getName())

            # We're done processing the Plist file, clean it up from our temporary directory.
            self.remove_from_temp_directory(file)

            # Update the progress bar, as progress has been made.
            filesProcessed += 1
            progressBar.progress(filesProcessed)

        # We're done. Post a status message for the user.
        IngestServices.getInstance().postMessage(
            IngestMessage.createMessage(IngestMessage.MessageType.DATA, self.moduleName,
                                        "Done processing %d OSX user accounts." % totalNumberFiles))

        return IngestModule.ProcessResult.OK

    # Given a Plist object obtained from biplist, iterate through and extract the information we're interested in.
    def extract_plist_data(self, plist):
        # Basic shell, will be returned at the end of all of this.
        extractedInformation = {'shadows': []}

        # Keys in the Plist that we're going to be extracting as strings.
        interestingStrKeys = ['uid', 'home', 'shell', 'realname', 'uid', 'hint', 'name', 'generateduuid', 'IsHidden']

        # Plist objects are stored values in an array by default.
        # If they don't exist, set them as an empty array, otherwise we really do nothing.
        for key in interestingStrKeys:
            try:
                extractedInformation[key] = plist.setdefault(key, [])[0]
            except (IndexError, KeyError):
                pass

        # accountPolicyData is where some basic information about the account is stored.
        if 'accountPolicyData' in plist and len(plist['accountPolicyData']):
            accountPolicyData = self.readPlistFromString(plist['accountPolicyData'][0])

            # Timestamp keys that we're interested in.
            interestingTsKeys = ['failedLoginTimestamp', 'creationTime', 'passwordLastSetTime']
            # Integer keys that we're interested in.
            interestingIntKeys = ['failedLoginCount']

            for key in interestingIntKeys:
                if key in accountPolicyData:
                    extractedInformation[key] = accountPolicyData[key]

            for key in interestingTsKeys:
                if key in accountPolicyData:
                    # Convert the String into a Long for Autopsy
                    extractedInformation[key] = long(float(accountPolicyData[key]))

        # ShadowHashData is where the account credentials are stored.
        if 'ShadowHashData' in plist:
            try:
                # as a Plist inside of the current Plist. Plist-ception.
                shadowHashPlist = self.readPlistFromString(plist['ShadowHashData'][0])
                # Multiple hash types can be stored inside of here - we want all of them.
                for hashType in shadowHashPlist:
                    hashDetails = {
                        'hashType': hashType,
                        'salt': '',
                        'entropy': '',
                        'iterations': '',
                        'verifier': '',
                        # hashcatEntry is not stored in the ShadowHashData - we'll be generating it later.
                        'hashcatEntry': '',
                    }

                    for key in shadowHashPlist[hashType]:
                        # We'll want to convert these into hex for storage
                        if key in ['salt', 'entropy', 'verifier']:
                            shadowHashPlist[hashType][key] = shadowHashPlist[hashType][key].encode('hex')

                        # Add what we find to our results
                        hashDetails[key] = shadowHashPlist[hashType][key]

                    # If the hash is of type SALTED-SHA512-PBKDF2,
                    # then we generate the hash that we would feed to Hashcat in the form of:
                    # $ml$(iterations)$(salt)$(first 128 bits of entropy)
                    if hashDetails['hashType'] == 'SALTED-SHA512-PBKDF2':
                        hashDetails['hashcatEntry'] = "$ml$%s$%s$%s" % (
                            hashDetails['iterations'], hashDetails['salt'], hashDetails['entropy'][:128])
                    else:
                        hashDetails['hashcatEntry'] = ''

                    # Add it to our list of found shadows
                    extractedInformation['shadows'].append(hashDetails)

            except (InvalidPlistException, NotBinaryPlistException), e:
                print "Not a plist:", e
        return extractedInformation

    def setup_custom_attribute_types(self):
        self.log(Level.INFO, "Setting up custom attribute types.")
        # Set up custom attribute types of OS Accounts
        for attribute in self.osAccountAttributeTypes:
            if self.osAccountAttributeTypes[attribute].setdefault('custom', False):
                self.create_custom_attribute_type(self.osAccountAttributeTypes[attribute]['attr_key'],
                                                  self.osAccountAttributeTypes[attribute]['attr_type'],
                                                  self.osAccountAttributeTypes[attribute]['display_name'])

        # Set up custom attribute types for hashed credentials.
        for attribute in self.hashedCredentialAttributeTypes:
            if self.hashedCredentialAttributeTypes[attribute].setdefault('custom', False):
                self.create_custom_attribute_type(self.hashedCredentialAttributeTypes[attribute]['attr_key'],
                                                  self.hashedCredentialAttributeTypes[attribute]['attr_type'],
                                                  self.hashedCredentialAttributeTypes[attribute]['display_name'])

        self.log(Level.INFO, 'Done setting up custom attribute types.')

    def create_custom_attribute_type(self, attr_key, attr_type, attr_display_name):
        try:
            self.case.addArtifactAttributeType(attr_key, attr_type, attr_display_name)
        except:
            self.log(Level.INFO,
                     "Exception while creating the \"%s\" Attribute Type." %
                     attr_display_name)

    def setup_custom_artifact_types(self):
        self.log(Level.INFO, "Setting up custom artifact types.")
        try:
            self.case.addArtifactType("TSK_HASHED_CREDENTIAL", "Hashed Credentials")
        except:
            self.log(Level.INFO,
                     "Exception while creating the TSK_HASHED_CREDENTIAL Artifact Type.")
        self.log(Level.INFO, "Done setting up custom artifact types.")

    # Read a string as a Plist
    # We have to use this instead of the biplist readPlistFromString method, as io.BytesIO is native
    def readPlistFromString(self, data):
        return readPlist(StringIO(data))

    # Given a file object, simply copies a file to a temporary location and returns the file path.
    def copy_to_temp_directory(self, file):
        filepath = self.get_temporary_file_path(file)
        ContentUtils.writeToFile(file, File(filepath))
        return filepath

    # Given a file object, removes it from the temporary directory.
    def remove_from_temp_directory(self, file):
        filepath = self.get_temporary_file_path(file)
        try:
            os.remove(filepath)
        except:
            self.log(Level.INFO, "Failed to remove file " + filepath)

    # Returns the location we should be storing temporary files.
    def get_temporary_file_path(self, file):
        return os.path.join(self.temporary_dir, str(file.getId()) + "-" + file.getName())
