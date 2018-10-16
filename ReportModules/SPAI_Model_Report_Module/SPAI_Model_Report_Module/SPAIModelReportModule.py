# -*- coding: UTF-8 -*-
# Autopsy report created for:
#   Danilo Caio Marcucci Marques
#   Computer Forensic Investigator - ICCE-DGPTC/PCERJ/Brazil
#
# Create by: Mark McKinnon, Mark.McKinnon@Davenport.edu or Mark.McKinnon@gmail.com 
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


# Meta Data html report module for Autopsy. 
#
# Create Oct 2017
#
# Version 1.0 - Initial creation - Oct 2017
#

import os
import inspect
import datetime
from java.lang import System
from java.util.logging import Level
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.report import GeneralReportModuleAdapter
from org.sleuthkit.autopsy.report.ReportProgressPanel import ReportStatus
from distutils.dir_util import copy_tree
from org.sleuthkit.autopsy.datamodel import ContentUtils
from java.io import File

from javax.swing import JCheckBox
from javax.swing import JButton
from javax.swing import ButtonGroup
from javax.swing import JTextField
from javax.swing import JLabel
from javax.swing import JList
from java.awt import GridLayout
from java.awt import GridBagLayout
from java.awt import GridBagConstraints
from javax.swing import JPanel
from javax.swing import JScrollPane
from javax.swing import JFileChooser
from javax.swing.filechooser import FileNameExtensionFilter


class SPAIModelReportModule(GeneralReportModuleAdapter):

    def __init__(self):
        self.tags_selected = []
        self.moduleName = "SPAI's HTML Model for Autopsy Report"
   
        self._logger = Logger.getLogger(self.moduleName)


    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def getName(self):
        return self.moduleName

    def getDescription(self):
        return "SPAI's HTML Model for Autopsy Report"

    def getRelativeFilePath(self):
        return "index.html"

    def getConfigurationPanel(self):
        self.artifact_list = []
        self.panel0 = JPanel()

        self.rbgPanel0 = ButtonGroup() 
        self.gbPanel0 = GridBagLayout() 
        self.gbcPanel0 = GridBagConstraints() 
        self.panel0.setLayout( self.gbPanel0 ) 

        self.Label_0 = JLabel("Number of Object to Display per page")
        self.gbcPanel0.gridx = 1 
        self.gbcPanel0.gridy = 1 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Label_0, self.gbcPanel0 ) 
        self.panel0.add( self.Label_0 ) 

        self.Num_Of_Objs_Per_Page_TF = JTextField(5) 
        self.Num_Of_Objs_Per_Page_TF.setEnabled(True)
        self.Num_Of_Objs_Per_Page_TF.setText("10")
        self.gbcPanel0.gridx = 3 
        self.gbcPanel0.gridy = 1 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Num_Of_Objs_Per_Page_TF, self.gbcPanel0 ) 
        self.panel0.add( self.Num_Of_Objs_Per_Page_TF ) 

        self.Blank_0 = JLabel( " ") 
        self.Blank_0.setEnabled(True)
        self.gbcPanel0.gridx = 1 
        self.gbcPanel0.gridy = 3
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Blank_0, self.gbcPanel0 ) 
        self.panel0.add( self.Blank_0 ) 

        self.Label_1 = JLabel("Title To Appear on Case Info")
        self.gbcPanel0.gridx = 1 
        self.gbcPanel0.gridy = 5 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Label_1, self.gbcPanel0 ) 
        self.panel0.add( self.Label_1 ) 

        self.Title_Case_TF = JTextField(30) 
        self.Title_Case_TF.setEnabled(True)
        self.Title_Case_TF.setText("Report of media analysis")
        self.gbcPanel0.gridx = 3 
        self.gbcPanel0.gridy = 5 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Title_Case_TF, self.gbcPanel0 ) 
        self.panel0.add( self.Title_Case_TF ) 


        self.Label_2 = JLabel("Report Number To Appear on Case Info")
        self.gbcPanel0.gridx = 1 
        self.gbcPanel0.gridy = 7 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Label_2, self.gbcPanel0 ) 
        self.panel0.add( self.Label_2 ) 

        self.Report_Number_TF = JTextField(30) 
        self.Report_Number_TF.setEnabled(True)
        self.Report_Number_TF.setText(Case.getCurrentCase().getNumber())
        self.gbcPanel0.gridx = 3 
        self.gbcPanel0.gridy = 7 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Report_Number_TF, self.gbcPanel0 ) 
        self.panel0.add( self.Report_Number_TF ) 

        self.Label_3 = JLabel("Examiner(s) To Appear on Case Info")
        self.gbcPanel0.gridx = 1 
        self.gbcPanel0.gridy = 9 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Label_3, self.gbcPanel0 ) 
        self.panel0.add( self.Label_3 ) 

        self.Examiners_TF = JTextField(30) 
        self.Examiners_TF.setEnabled(True)
        self.Examiners_TF.setText(Case.getCurrentCase().getExaminer())
        self.gbcPanel0.gridx = 3 
        self.gbcPanel0.gridy = 9
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Examiners_TF, self.gbcPanel0 ) 
        self.panel0.add( self.Examiners_TF ) 

        self.Label_4 = JLabel("Description To Appear on Case Info")
        self.gbcPanel0.gridx = 1 
        self.gbcPanel0.gridy = 11 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Label_4, self.gbcPanel0 ) 
        self.panel0.add( self.Label_4 ) 

        self.Description_TF = JTextField(30) 
        self.Description_TF.setEnabled(True)
        #self.Description_TF.setText(Case.getCurrentCase().getNumber())
        self.gbcPanel0.gridx = 3 
        self.gbcPanel0.gridy = 11 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Description_TF, self.gbcPanel0 ) 
        self.panel0.add( self.Description_TF ) 

        self.Blank_4 = JLabel( " ") 
        self.Blank_4.setEnabled(True)
        self.gbcPanel0.gridx = 1 
        self.gbcPanel0.gridy = 19
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Blank_4, self.gbcPanel0 ) 
        self.panel0.add( self.Blank_4 ) 

        self.Label_5 = JLabel( "Tags to Select for Report:") 
        self.Label_5.setEnabled(True)
        self.gbcPanel0.gridx = 1 
        self.gbcPanel0.gridy = 21
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Label_5, self.gbcPanel0 ) 
        self.panel0.add( self.Label_5 ) 

        self.List_Box_LB = JList( self.find_tags(), valueChanged=self.onchange_lb)
        self.List_Box_LB.setVisibleRowCount( 3 ) 
        self.scpList_Box_LB = JScrollPane( self.List_Box_LB ) 
        self.gbcPanel0.gridx = 1 
        self.gbcPanel0.gridy = 23 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 1 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.scpList_Box_LB, self.gbcPanel0 ) 
        self.panel0.add( self.scpList_Box_LB ) 

        self.Blank_5 = JLabel( " ") 
        self.Blank_5.setEnabled(True)
        self.gbcPanel0.gridx = 1 
        self.gbcPanel0.gridy = 25
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Blank_5, self.gbcPanel0 ) 
        self.panel0.add( self.Blank_5 ) 

        #self.add(self.panel0)
        return self.panel0
        
    def generateReport(self, baseReportDir, progressBar):

        progressBar.setIndeterminate(False)
        progressBar.start()

        # Set status bar for number of tags
        progressBar.setMaximumProgress(2)

        
        # Get and create the report directories
        head, tail = os.path.split(os.path.abspath(__file__)) 
        copy_resources_dir = os.path.join(head, "res")
        try:
            report_dir = os.path.join(baseReportDir, "Report")
            os.mkdir(report_dir)
        except:
            self.log(Level.INFO, "Could not create base report dir")
            
        try:
            report_files_dir = os.path.join(report_dir, "report_files")
            os.mkdir(report_files_dir)
        except:
            self.log(Level.INFO, "Could not create report_files directory")
         
        try:
            report_resources_dir = os.path.join(report_dir, "res")
            os.mkdir(report_resources_dir)
        except:
            self.log(Level.INFO, "Could not create report_res directory")
            
        # Copy the Resource directory to the report directory
        try:
            head, tail = os.path.split(os.path.abspath(__file__)) 
            copy_resources_dir = os.path.join(head, "res")
            copy_tree(copy_resources_dir, report_resources_dir)
        except:
            self.log(Level.INFO, "Could Not copy resources directory")

        # Copy the base files needed for the report
        try:
            copy_base_dir = os.path.join(head, "base_folder")
            copy_tree(copy_base_dir, report_dir)
        except:
            self.log(Level.INFO, "Could not write files from base_folder to base_report_Folder")
            
        # Create the index page        
        self.create_index_file(report_dir)
        
        # Create The information page
        self.create_info_page(report_dir)

        # Create the Menu page.
        self.create_menu_file(report_dir)

        # Get all Content
        tags = Case.getCurrentCase().getServices().getTagsManager().getAllContentTags()
        tag_number = 1
        for sel_tag in self.tags_selected:
            tags_to_process = []
            for tag in tags:
                if tag.getName().getDisplayName() == sel_tag:
                    tags_to_process.append(tag)
                    self.log(Level.INFO, "this is a content tags ==> " + tag.getName().getDisplayName() + " <==")
            progressBar.updateStatusLabel("Process tag " + sel_tag)
            self.process_thru_tags(report_dir, tags_to_process, tag_number, sel_tag, report_files_dir)
            tag_number = tag_number + 1
        
        # Increment since we are done with step #1
        progressBar.increment()

        fileName = os.path.join(report_dir, "index.html")

        # Add the report to the Case, so it is shown in the tree
        Case.getCurrentCase().addReport(fileName, self.moduleName, "SPAI's HTML Model Report")

        progressBar.increment()

        # Call this with ERROR if report was not generated
        progressBar.complete(ReportStatus.COMPLETE)

    def process_thru_tags(self, report_dir, tags_to_process, book_mark_number, tag_name, report_files_dir):
        page_number = 1
        current_page_number = 1
        num_of_tags_per_page = int(str(self.Num_Of_Objs_Per_Page_TF.getText()))
        total_pages = int(len(tags_to_process))//num_of_tags_per_page
        if (int(len(tags_to_process)) % num_of_tags_per_page) <> 0:
            total_pages = total_pages + 1
        page_file_name = os.path.join(report_dir, "Bookmark" + str(book_mark_number) + "Pagina" + str(page_number) + ".html")
        page_file = open(page_file_name, 'w')
        self.create_page_header(page_file, len(tags_to_process), tag_name, total_pages)
        tag_number = 1
        total_tag_number = 1
        for tag in tags_to_process:
            if tag_number > num_of_tags_per_page:
                tag_number = 1
                page_number = page_number + 1
                page_file_name = os.path.join(report_dir, "Bookmark" + str(book_mark_number) + "Pagina" + str(page_number) + ".html")
                self.create_page_footer(page_file, total_pages, current_page_number, "Bookmark" + str(book_mark_number) + "Pagina")
                page_file.close()
                #page_file_name = os.path.join(report_dir, "Bookmark" + str(tag_number) + "Pagina1.html")
                page_file = open(page_file_name, 'w')
                self.create_page_header(page_file, len(tags_to_process), tag_name, current_page_number)
                current_page_number = current_page_number + 1
            self.create_page_data(page_file, tag, total_tag_number, report_files_dir)
            tag_number = tag_number + 1
            total_tag_number = total_tag_number + 1
        self.create_page_footer(page_file, total_pages, current_page_number, "Bookmark" + str(book_mark_number) + "Pagina")
        page_file.close()

    def create_page_footer(self, page_file, total_pages, current_page, page_file_name):
        page_file.write('<!--          Rodape        -->')
        page_file.write('	<table width="100%">')
        page_file.write('		<tr>')
        page_file.write('			<td><small> ' + datetime.datetime.today().strftime('%d/%m/%Y') + ' </small></td>')

        if current_page < total_pages:
            if current_page < total_pages:
                if current_page == 1:
                    page_file.write('			<td>Page ' + str(current_page) + ' of ' + str(total_pages) + ' </td>')
                    page_file.write('      <td><a href="' + page_file_name + str(current_page + 1) + ".html" + '">next page &gt;&gt</a></td>')
                else:
                    page_file.write('      <td><a href="' + page_file_name + str(current_page - 1) + ".html" + '">&lt;&lt;Previous page</a></td>')
                    page_file.write('			<td>Page ' + str(current_page) + ' of ' + str(total_pages) + ' </td>')
                    page_file.write('      <td><a href="' + page_file_name + str(current_page + 1) + ".html" + '"> next page &gt;&gt</a></td>')
            elif current_page == total_pages:
                page_file.write('      <td><a href="' + page_file_name + str(current_page - 1) + ".html" + '">&lt;&lt;Previous page</a></td>')
                page_file.write('			<td>Page ' + str(current_page) + ' of ' + str(total_pages) + ' </td>')
            else:
                page_file.write('			<td>Page ' + str(current_page) + ' of ' + str(total_pages) + ' </td>')
        else:
            if current_page == 1:        
                page_file.write('			<td>Page 1 of 1 </td>')             
            else:
                page_file.write('      <td><a href="' + page_file_name + str(current_page - 1) + ".html" + '">&lt;&lt;Previous page</a></td>')
                page_file.write('			<td>Page ' + str(current_page) + ' of ' + str(total_pages) + ' </td>')

        page_file.write('		</tr>')
        page_file.write('	</table>')
        page_file.write(' ')
        page_file.write('	<p><img border="0" src="res/Footer.gif"/></p>')
        page_file.write('</body>')
        page_file.write('</html>')
        page_file.write('<!--          Rodape        -->')

    def create_page_data(self, page_file, tag, tag_number, report_files_dir):
        try:
            tag_content = tag.getContent()
            lclDbPath = os.path.join(report_files_dir, str(tag_content.getId()) + "-" + tag_content.getName())
            ContentUtils.writeToFile(tag_content, File(lclDbPath))

            page_file.write('	<div class="clrBkgrnd bkmkSeparator bkmkValue">')
            page_file.write('		<span style="FONT-WEIGHT:bold">Metadata: </span>')
            page_file.write('	</div>')
            page_file.write(' ')
            page_file.write('	<div class="row">')
            page_file.write('		<span class="bkmkColLeft bkmkValue labelBorderless clrBkgrnd" width="100%" border="1">Index</span>')
            page_file.write('		<span class="bkmkColRight bkmkValue"> ' + str(tag_number) + ' </span>')
            page_file.write('	</div>')
            page_file.write(' ')
            page_file.write('	<div class="row">')
            page_file.write('		<span class="bkmkColLeft bkmkValue labelBorderless clrBkgrnd" width="100%" border="1">Name</span>')
            page_file.write('		<span class="bkmkColRight bkmkValue"> ' + tag_content.getName() + ' </span>')
            page_file.write('	</div>')
            page_file.write(' ')
            page_file.write('	<div class="row">')
            page_file.write('		<span class="bkmkColLeft bkmkValue labelBorderless clrBkgrnd" width="100%" border="1">Path</span>')
            page_file.write('		<span class="bkmkColRight bkmkValue"> ' + tag_content.getUniquePath() + ' </span>')
            page_file.write('	</div>')
            page_file.write(' ')
            page_file.write('	<div class="row">')
            page_file.write('		<span class="bkmkColLeft bkmkValue labelBorderless clrBkgrnd" width="100%" border="1">Logical size</span>')
            page_file.write('		<span class="bkmkColRight bkmkValue"> ' + str(tag_content.getSize()) + ' </span>')
            page_file.write('	</div>')
            page_file.write(' ')
            page_file.write('	<div class="row">')
            page_file.write('		<span class="bkmkColLeft bkmkValue labelBorderless clrBkgrnd" width="100%" border="1">Created</span>')
            page_file.write('		<span class="bkmkColRight bkmkValue"> ' + tag_content.getCrtimeAsDate() + ' </span>')
            page_file.write('	</div>')
            page_file.write(' ')
            page_file.write('	<div class="row"> ')
            page_file.write('		<span class="bkmkColLeft bkmkValue labelBorderless clrBkgrnd" width="100%" border="1">Modified</span>')
            page_file.write('		<span class="bkmkColRight bkmkValue"> ' + tag_content.getMtimeAsDate() + ' </span>')
            page_file.write('	</div>')
            page_file.write(' ')
            page_file.write('	<div class="row">')
            page_file.write('		<span class="bkmkColLeft bkmkValue labelBorderless clrBkgrnd" width="100%" border="1">Accessed</span>')
            page_file.write('		<span class="bkmkColRight bkmkValue"> ' + tag_content.getAtimeAsDate() + ' </span>')
            page_file.write('	</div>')
            page_file.write(' ')
            page_file.write('	<div class="row">')
            page_file.write('		<span class="bkmkColLeft bkmkValue labelBorderless clrBkgrnd" width="100%" border="1">Deleted</span>')
            page_file.write('		<span class="bkmkColRight bkmkValue"> ' )
            if tag_content.exists():
                page_file.write('No' + ' </span>')
            else:
                page_file.write('Yes' + '</span>')
            page_file.write('	</div>')
            page_file.write(' ')
            page_file.write('	<div class="row">')
            page_file.write('		<span class="bkmkColLeft bkmkValue labelBorderless clrBkgrnd" width="100%" border="1">Exported as</span>')
            page_file.write('		<span class="bkmkColRight bkmkValue">report_files\ ' + tag_content.getName() + ' </span>')
            page_file.write('	</div>')
            page_file.write(' ')
            page_file.write('	<div class="row">')
            page_file.write('		<span class="bkmkColLeft bkmkValue labelBorderless clrBkgrnd" width="100%" border="1">Preview</span>')
            self.log(Level.INFO, 'File Extension ==> ' + tag_content.getNameExtension())
            if tag_content.getNameExtension() in ['jpg','png']:
                page_file.write('<table width="100%">')
                page_file.write('    <tr>')
                page_file.write('        <td align="center" class="">')
                page_file.write('            <a href="report_files\\' + str(tag_content.getId()) + '-' + tag_content.getName() + '"/>')
                page_file.write('            <img src="report_files\\' + str(tag_content.getId()) + '-' + tag_content.getName() + '" alt="report_files\\' + tag_content.getName() + '" width="96" height="96"/>')
                page_file.write('        </td>')
                page_file.write('    </tr>')
                page_file.write('</table>')
            else:
                page_file.write('		<span class="bkmkColRight bkmkValue">')
                page_file.write('			<a href="report_files\\' + str(tag_content.getId()) + '-' + tag_content.getName() + '">' + tag_content.getName() + '</a>')
            page_file.write('		</span>')
            page_file.write('	</div>')
        except:
            self.log(Level.INFO, "File Content Not written or created ==> " + str(tag_content.getId()) + '-' + tag_content.getName())
            
    def create_page_header(self, page_file, number_of_tags, tag_name, page_number):
        page_file.write('<!--          Cabecalho        -->')
        page_file.write('<?xml version="1.0" encoding="UTF-8"?>')
        page_file.write('<html xmlns="http://www.w3.org/1999/xhtml">')
        page_file.write(' ')
        page_file.write('<head>')
        page_file.write('	<meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>')
        page_file.write('	<link rel="stylesheet" type="text/css" href="res/common.css"/>')
        page_file.write('	<link rel="stylesheet" type="text/css" href="res/Bookmarks.css"/>')
        page_file.write('	<title>Tags</title>')
        page_file.write('</head>')
        page_file.write(' ')
        page_file.write(' ')
        page_file.write('<body>')
        page_file.write('	<table>')
        page_file.write('		<tr><td height="20" valign="top"><img border="0" src="res/Header.gif"/></td></tr>')
        page_file.write('	</table>')
        page_file.write(' ')
        page_file.write('	<table width="100%">')
        page_file.write('		<tr>')
#        page_file.write('			<td><small> ' + datetime.datetime.today().strftime('%d/%m-%Y') + ' </small></td>') # Danilo C M Marques - 27/10/2017
        page_file.write('			<td><small> ' + datetime.datetime.today().strftime('%d/%m/%Y') + ' </small></td>') # Danilo C M Marques - 27/10/2017
        page_file.write('			<td>Page 1 of ' + str(page_number) + ' </td>')
        page_file.write('		</tr>')
        page_file.write('	</table>')
        page_file.write(' ')
        page_file.write('	<table width="100%">')
        page_file.write('		<tr><th class="columnHead" colspan="1">Tag: <span style="font-size:1.25em">' + tag_name.encode('utf-8') + '</span></th></tr>')
        page_file.write('		<tr><td class="clrBkgrnd"><span style="font-weight:bold">Number of files: </span>' + str(number_of_tags) + ' </td></tr>')
        page_file.write('	</table>')
        page_file.write(' ')
        page_file.write('	</br></br>')
        page_file.write(' ')
        page_file.write('	<div class="bkmkLblFiles" width="100%" border="1">Files</div>')
        page_file.write('	<a name="bk_obj13550"> </a>')
        page_file.write('<!--          Cabecalho        -->')
        page_file.write(' ')
        page_file.write(' ')
        page_file.write(' ')
        page_file.write(' ')
        
    def create_index_file(self, report_dir):
        index_file_name = os.path.join(report_dir, "index.html")
        index_file = open(index_file_name, 'w')
        index_file.write('<?xml version="1.0" encoding="UTF-8"?>')
        index_file.write('<html xmlns="http://www.w3.org/1999/xhtml">')
        index_file.write(" ")
        index_file.write("<head>")
        index_file.write('	<meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>')
#        index_file.write("	<title> " + 'Instituto de Criminalística Carlos Éboli - DGPTC/PCERJ' + "</title>") # Danilo C M Marques - 27/10/2017
        index_file.write("	<title> " + 'My Institution' + "</title>") # Danilo C M Marques - 27/10/2017
        index_file.write("</head>")
        index_file.write(" ")
        index_file.write('<frameset cols="290,10%">')
        index_file.write('	<frame src="Menu.html" name="navigate" frameborder="0"/>')
        index_file.write('	<frame src="Informacoes.html" name="contents" frameborder="1"/>')
        index_file.write("	<noframes/>")
        index_file.write("</frameset>")
        index_file.write(" ")
        index_file.write("</html>")
        index_file.close()
        
    def create_info_page(self, report_dir):
        # get case specific information to put in the information.html file
        skCase = Case.getCurrentCase()
 
        # Open and write information.html file
        info_file_name = os.path.join(report_dir, "Informacoes.html")
        info_file = open(info_file_name, 'w')
        info_file.write('<?xml version="1.0" encoding="UTF-8"?>')
        info_file.write('<html xmlns="http://www.w3.org/1999/xhtml">')
        info_file.write(" ")
        info_file.write("<head>")
        info_file.write('	<meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>')
        info_file.write('	<link rel="stylesheet" type="text/css" href="res/common.css"/>')
        info_file.write("	<title>Case Information</title>")
        info_file.write("</head>")
        info_file.write(" ")
        info_file.write(" ")
        info_file.write(" ")
        info_file.write(" ")
        info_file.write("<body>")
        info_file.write(" ")
        info_file.write('	<div class="bkmkColHead" width="100%" border="1">Case information</div>')
        info_file.write('	<table width="100%">')
        info_file.write("		<tr>")
        info_file.write('			<td style="width:20%" class="bkmkValue labelBorderless clrBkgrnd">Title</td>')
        info_file.write("			<td> " + self.Title_Case_TF.getText() + " </td>")
        info_file.write("		</tr>")
        info_file.write(" ")
        info_file.write("		<tr>")
        info_file.write('			<td style="width:20%" class="bkmkValue labelBorderless clrBkgrnd">Report number</td>')
        info_file.write("			<td> " + self.Report_Number_TF.getText() + "</td>")
        info_file.write("		</tr>")
        info_file.write(" ")
        info_file.write("		<tr>")
        info_file.write('			<td style="width:20%" class="bkmkValue labelBorderless clrBkgrnd">Examiner(s)</td>')
        info_file.write("			<td> " + self.Examiners_TF.getText() + " </td>")
        info_file.write("		</tr>")
        info_file.write(" ")
        info_file.write("		<tr>")
        info_file.write('			<td style="width:20%" class="bkmkValue labelBorderless clrBkgrnd">Description</td>')
        info_file.write("			<td> " + self.Description_TF.getText() + " </td>")
        info_file.write("		</tr>")
        info_file.write(" ")
        info_file.write("		<tr>")
        info_file.write('			<td style="width:20%" class="bkmkValue labelBorderless clrBkgrnd">ATTENTION</td>')
        info_file.write("			<td>It is recommended to configure the browser to offline mode, in order to avoid that HTML temporary files be visualized in external servers</td>")
        info_file.write("		</tr>")
        info_file.write("	</table>")
        info_file.write('	<p><img border="0" src="res/Footer.gif"/></p>')
        info_file.write(" ")
        info_file.write("</body>")
        info_file.write("</html>")
        
        # Close Info File        
        info_file.close()
        
    def create_menu_file(self, report_dir):    
        # get case specific information to put in the information.html file
        skCase = Case.getCurrentCase()
 
        # Open and write information.html file
        menu_file_name = os.path.join(report_dir, "menu.html")
        menu_file = open(menu_file_name, 'w')
        
        menu_file.write('<?xml version="1.0" encoding="UTF-8"?>')
        menu_file.write('<html xmlns="http://www.w3.org/1999/xhtml">')
        menu_file.write(' ')
        menu_file.write('<head>')
        menu_file.write('	<meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>')
        menu_file.write('	<link rel="stylesheet" type="text/css" href="res/navigation.css"/>')
        menu_file.write('	<link rel="stylesheet" type="text/css" href="res/common.css"/>')
        menu_file.write('	<title>Summary</title>')
        menu_file.write('</head>')
        menu_file.write(' ')
        menu_file.write('<body background="res/Background.gif">')
        menu_file.write(' ')
        menu_file.write('<!--	<img style="margin: 0px 70px" border="0" src="res/brasao.gif"/>-->')
        menu_file.write('	<img style="margin: 0px 70px" border="0" src="res/icon.ico"/>')
        menu_file.write('	<p> </p>')
        menu_file.write('	<div>')
        menu_file.write('		<h3><font color="white">Summary of Analysis<h3>')
        menu_file.write('		<a class="sectionLinks" target="contents" href="Informacoes.html">')
        menu_file.write('			<span style="margin-left:15px"> Case Information </span>')
        menu_file.write('		</a>')
        menu_file.write('		<div> </div>')
        menu_file.write('		<a class="sectionLinks" target="contents" href="Ajuda.htm">')
#        menu_file.write('			<span style="margin-left:15px">Ajuda</span>') # Danilo C M Marques - 27/10/2017
        menu_file.write('			<span style="margin-left:15px">Help</span>')
        menu_file.write('		</a>')
        menu_file.write('		<div> </div> ')
        menu_file.write('		<h3>Selected Evidences<h3>')
        tag_number = 1
        for tag in self.tags_selected:
            menu_file.write('		<a class="sectionLinks" target="contents" href="Bookmark' + str(tag_number) + 'Pagina1.html">')
            menu_file.write('			<span style="margin-left:30px">' + tag.encode('utf-8') + '</span>')
            menu_file.write('		</a>')
            tag_number = tag_number + 1
        menu_file.write(' ')
        menu_file.write('	</div>')
        menu_file.write(' ')
        menu_file.write('</body>')
        menu_file.write('</html>')
        menu_file.close()

    def onchange_lb(self, event):
        self.tags_selected[:] = []
        self.tags_selected = self.List_Box_LB.getSelectedValuesList()


    def find_tags(self):
        tag_list = []
        sql_statement = "SELECT distinct(display_name) u_tag_name FROM content_tags INNER JOIN tag_names ON " + \
                        " content_tags.tag_name_id = tag_names.tag_name_id;"
        skCase = Case.getCurrentCase().getSleuthkitCase()
        dbquery = skCase.executeQuery(sql_statement)
        resultSet = dbquery.getResultSet()
        while resultSet.next():
             tag_list.append(resultSet.getString("u_tag_name"))
        dbquery.close()
        return tag_list 