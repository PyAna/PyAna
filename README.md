# PyAna
- PyAna - Analyzing the Windows shellcode.
Using Unicorn Framework for emulating shellcode. PyAna emulate a process on Windows: PEB, TIB, LDR_MODULE to create a emulative environment.

#Usage
- From command line type: PyAna.py [shellcode]

#Dependencies
 -This tool depend on  Unicorn Framework developing by Nguyen Anh Quynh. Download and install them at http://www.unicorn-engine.org/.
#Status
- Implement in Python using Unicorn binding
- Emulating  a simple shellcode: calc, UrlDownloadToFile
- Windows system structure emulator is not completely
- A few of Win32 API hooking
#TODO
- analyzing PE file on Windows
- support unpacking
- apply on fuzzing, exploit detection.
#Under development.
 
