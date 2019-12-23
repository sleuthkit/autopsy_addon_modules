# Autopsy 3rd Party Module Repository

This repository contains the 3rd party Autopsy add-on modules.  You have two choices for using it.

1. Make a copy of this repository by downloading a ZIP file of it.  You can do this by clicking on "Clone or download" and then "Download ZIP". 
![Download Image](images/download.png) 

2. You can download specific modules from the site.  This is easier for Java NBM modules than it is for Python modules, which may contain a number of files. 

The modules are organized by their type. 
- Ingest modules analyze files as they are added to the case.  This is most common type of module.
- Content viewer modules are in the lower right corner of Autopsy and they display a file or selected item in some way.
- Report modules run at the end of the analysis and can generate various types of reports (or can do various types of analysis).
- Data source processors allow for different types of data sources to be added to a case. 

Each module has its own folder with a README.md file that outlines the basics of what the module does. 

Instructions for installing a module can be found here: http://sleuthkit.org/autopsy/docs/user-docs/4.9.0/module_install_page.html

NOTE: This replaces the wiki page that was here: http://wiki.sleuthkit.org/index.php?title=Autopsy_3rd_Party_Modules

[Instructions for Developers](DocsForDevelopers/DeveloperInstructions.md)
