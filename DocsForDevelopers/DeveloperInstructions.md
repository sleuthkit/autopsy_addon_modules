This document outlines how to get your Autopsy module into this repository.  The goal of this repository is to make it easy for Autopsy users to get the latest versions of modules and know what modules exist.  

Our goal is to make this as simple as possible for you so that you can get the biggest userbase for your module. 

1. Fork this repo so that you can make a pull request. 
2. Make a folder in the appropriate folder based on your type of module.  Folder name should be descriptive about what it does. 
3. Copy the DocsForDevelopers/README_template.md file into your folder and name it README.md.
4. Fill in as much README.md info as possible and add more items that you think are relevant.
5. Decide where you will be storing the module.  Options include:
 - Place a copy of the NBM or Python ZIP file into the current folder.
 - If the NBM or ZIP file contains several modules and each has its own folder, then pick which folder will contain the NBM or ZIP and the other folders should refer to that folder in the README.md.  We do not want multiple copies of the same NBM/ZIP. 
 - Host the NBM or ZIP on your own site and put the URL into the README.md. 
5. Copy your NBM or Python ZIP file into the folder.  Or, if you would prefer to host the module, then ensure that the URL is listed in the README.md file. 
6. Submit a pull request. 

If you have any questions, please create an Issue on the repository. 

