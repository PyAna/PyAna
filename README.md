# PyAna
PyAna - Analyzing the Windows shellcode.
Using Unicorn Framework for emulating shellcode. PyAna emulate a process on Windows: PEB, TIB, LDR_MODULE to create a emulative environment.

# Usage
    -From commandline type: PyAna.py [shellcode]
# Dependencies
-PyAna depends on :
* [Unicorn Framework] developing by Nguyen Anh Quynh. 
* [pefile] developing by Ero Carrera
# Status
* Implement in Python using Unicorn binding
* Emulating  a simple shellcode: calc, UrlDownloadToFile
* Windows system structure emulator is not completely
* A few of Win32 API hooking
# TODO
* support PE file on Windows
* support unpacking
* apply on fuzzing, exploit detection.
# Under development.
 [//]: # (these are link referrence for dependencies packages)
   [Unicorn Framework]: <http://www.unicorn-engine.org/>
   [pefile]: <https://github.com/erocarrera/pefile>
   