- __Description:__ Parser for Microsoft Office Telemetry files (.tbl).
- __Author:__ Sam Koffman <sam@madscientistassociation.org>
- __Minimum Autopsy version:__ 4.8.0
- __Module Location__: https://github.com/MadScientistAssociation/Autopsy-MSOT
- __Website:__ https://madscientistassociation.org
- __Source Code:__ https://github.com/MadScientistAssociation/Autopsy-MSOT
- __License:__ MIT License

# Microsoft Office Telemetry Parser for Autopsy

## Overview

In Office 2013, Microsoft introduced telemetry collection in Office. This created a gold mine of data for digital forensics examiners.

Included in Office telemetry collection are:
* File name
* User name
* File open/close date/times
* File size
* Document title
* Document author
* Office version
* Last loaded date/times

This ingest module searches for folders containing all three of the files sln.tbl, user.tbl, and evt.tbl. It then combines the data from these 3 files and outputs artifacts to the blackboard as type TSK_RECENT_OBJECT.

## Usage

Unzip all files from the repo into an unique folder in the Autopsy Python directory.

## License

This project constitutes a work of the United States Government and is not subject to domestic copyright protection under 17 USC § 105.

However, because the project utilizes code licensed from contributors and other third parties, it therefore is licensed under the MIT License. http://opensource.org/licenses/mit-license.php. Under that license, permission is granted free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the conditions that any appropriate copyright notices and this permission notice are included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
