#PyAna
PyAna - Analyzing the Windows shellcode. 
Using Unicorn Framework for emulating shellcode. PyAna emulate a process on Windows: PEB, TIB, LDR_MODULE to create a emulative environment. 

#Usage
* From commandline type: PyAna.py [shellcode]
* Ex: PyAna.py  Samples/UrlDownloadToFile.sc
* Show report:

    ![report](http://i.imgur.com/OvMNhSU.png)

#Dependencies
PyAna depends on :
* [Unicorn Framework] & [Capstone] developing by Nguyen Anh Quynh.
* [pefile] developing by Ero Carrera

#Status
* Implement in Python using Unicorn binding
* Emulating  a simple shellcode: calc, UrlDownloadToFile
* Windows system structure emulator is not complete
* A few of Win32 API hooking
* Only support 32 bit

#TODO
* support PE file on Windows
* support unpacking
* apply on fuzzing, exploit detection.

#Under development.
[//]: # (these are link referrence for dependencies packages)
   [Unicorn Framework]: <http://www.unicorn-engine.org/>
   [pefile]: <https://github.com/erocarrera/pefile>
   [Capstone]: <http://www.capstone-engine.org>