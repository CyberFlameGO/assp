Installation:

copy the content of the zip file to your assp folder and restart assp.



How to start:

use the url http[s]//your.assp:webport/fc

or use the link in the left top menu of the main assp GUI



Requirements:

- assp version 2 build 13264 or higher
- Perl modules:

Archive::Extract
Archive::Zip
Archive::Tar
IO::Compress::Gzip
IO::Compress::Bzip2
Email::MIME


Recommended:

- windows: install the perl module Win32::DriveInfo via ppm

- all other operating systems: install the perl module Filesys::DiskSpace via cpan



Usage:

- one click on a folder or file toggles the mark of the entry
- double click on a folder, opens the folder
- double click on a file, views the file or opens the compressed file
- double click on a *.ppd file will try to install the module package
- use the icons to select , unselect and to toggle the complete selection of folders and files
- use the checkboxes to hid or display columns
- to change the sorting, click on the column header
- to change the column width move the column header separators


Limitations:

- the [view],[edit] and [analyze] actions are limited to three file at ones, even if more files are selected
- keep in mind, that all actions [copy], [move], [rename] and [delete] are done with the permission of the user profile
  the assp process in running with!
- operations on .pl, .pm, .cfg and .js files are only permitted to the root user
- access to configuration files follows the rules defined for the admin user  
- copying .eml files will not process them to change the whitelist or personal blacklist - if you want assp to do this,
  use the [edit] action and copy or move the file in the edit-dialog
- download only uses the first found (selected) file (1.left, 2.right)
- upload is limited to one file at a time - upload is done to the folder shown in the left panel 
- only in the left panel selected files could be compressed
