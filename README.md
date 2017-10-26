# Ghost in the Shell
Ghost in the shell php file security scanner

## info
This is a security scanner for php. Nothing fancy, just checks for some 
common patterns, dirs and files that may be present on a site or webapp, 
and ofcourse, evaled of encoded php code 
Requires php version 5.4+

## usage:

php gis.php file_to_scan  
php gis.php dir_to_scan  
php gis.php (inside a dir to scan with an "." as argument scans everything inside that dir including subdirs)  
php gis.php -<options> file_or_dir_to_scan  

### options:

f = full log  
n = filename only log  
j = json format log  
o = no logfile creation  
s = silent, no output  
p = print filenames being scanned instead of dots  
a = scan all files not only php  
i = scan for fake images (php scripts with image filename/extension)  

For now the last 2 options dont work.

This programm is still in alpha stage so do not use it blindly, do also a manual check in suspected web sites or/and use some other scanner too.
