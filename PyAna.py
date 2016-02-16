#!/usr/bin/python

# Analyzing emulator for Win32 shellcode
# Development base on Unicorn Framework- Nguyen Anh Quynh
# copyright by Nguyen Van Luc
from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
from capstone import *
import struct
import pefile
import sys
import os
import tempfile


kr32='kernelkernel32.dll'
#kr32=('k',0,'e',0,'r',0,'n',0,'e',0,'l',0,'3',0,'2',0,'.',0,'d',0,'l',0,'l',0)
def input_shellcode():
    if len(sys.argv) !=2:
        print('\n[+]Usage:' + sys.argv[0] + ' [shellcode]\n')
        exit(0)
    # get shellcode for emulation
    fShell=open(sys.argv[1],'rb')
    shellcode=fShell.read()
    fShell.close()
    return shellcode



#Initial memory layout for emulation
FS=0x1000
ADDRESS=0x40100
DLL_BASE=0x78000
PageSize=0x80000 # 512kB
#map Win32 API address and name function
imp_des={}

#CreationDisposition for File access
CreationDisposition={1:'CREATE_AWAYS',2:'CREATE_NEW',3:'OPEN_EXISTING',4:'OPEN_ALWAYS',5:'TRUNCATE_EXISTING'}

# get 1 dword from Stack
def pops(uc,ESP):
    esp=uc.mem_read(ESP,4)
    esp=struct.unpack('<I',esp)[0]
    return esp
def string_pack(argv):
    s=''
    for c in argv:
        if(c==0):
            break
        s+=chr(c)
    return s

''' 
	hook GetTempPathA(lBuff, lpBuff)
'''
def hook_GetTempPathA(id,esp,uc):
    lBuffer=pops(uc,esp+4)
    pBuffer=pops(uc,esp+8)
    eip_saved=pops(uc,esp)
    tempPath='\\temp\\'
    uc.mem_write(pBuffer,tempPath)
    uc.reg_write(UC_X86_REG_ESP,esp+0x08)
    uc.reg_write(UC_X86_REG_EAX,len(tempPath))
    print('0x%0.2x:\tcall GetTempPathA(len=0x%0.2x, buf=0x%0.2x)' % (eip_saved,lBuffer,pBuffer))
    #esp=uc.reg_read(UC_X86_REG_ESP)
    eip_packed=struct.pack('<I',eip_saved)
    uc.mem_write(esp+0x08,eip_packed)
	
'''
	hook WinExec(cmd,nShow)
'''
def hook_WinExec(id,esp,uc):
    pCmd=pops(uc,esp+4)
    nshow=pops(uc,esp+8)
    eip_saved=pops(uc,esp)
    CMD=uc.mem_read(pCmd,0x100)
    cmd=string_pack(CMD)
    uc.reg_write(UC_X86_REG_ESP,esp+0x08)
    print('0x%0.2x:\tcall WinExec(\'%s\', %d)' % (eip_saved,cmd,nshow))
    eip_packed=struct.pack('<I',eip_saved)
    uc.mem_write(esp+0x08,eip_packed)
	
'''
	hook LoadLIbraryA(lpLib)
'''
def hook_LoadLibraryA(id,esp,uc):
    pLib=pops(uc,esp+4)
    eip_saved=pops(uc,esp)
    LIB=uc.mem_read(pLib,16)
    lib=string_pack(LIB)
    print('0x%0.2x:\tcall LoadLibraryA(\'%s\')' % (eip_saved,lib))
    baseLB=DLL_BASE+2*PageSize
    LB=dll_loader(lib,baseLB)
    uc.mem_write(baseLB,LB)
    uc.reg_write(UC_X86_REG_EAX,baseLB)
    #uc.reg_write(UC_X86_REG_EIP,eip_saved)
    uc.reg_write(UC_X86_REG_ESP,esp+4)
    eip_packed=struct.pack('<I',eip_saved)
    uc.mem_write(esp+4,eip_packed)
	
'''
	hook UrlDownloadToFile( pCaller,szURL,szFileName,
						  dwReserved,lpfnCB)
'''
def hook_URLDownloadToFileA(id,esp,uc):
    eip_saved=pops(uc,esp)
    pUrl=pops(uc,esp+8)
    pFileName=pops(uc,esp+0x0c)
    szUrl=uc.mem_read(pUrl,0x100)
    szFileName=uc.mem_read(pFileName,0x100)
    Url=string_pack(szUrl)
    FileName=string_pack(szFileName)
    print('0x%0.2x:\tcall URLDownloadToFileA(Url=%s, LocalPath=%s)' % (eip_saved,Url,FileName))
    uc.reg_write(UC_X86_REG_ESP,esp+0x14)
    eip_packed=struct.pack('<I',eip_saved)
    uc.mem_write(esp+0x14,eip_packed)
'''
	hook ExitProcess (uExitcode)
'''
def hook_ExitProcess(id,esp,uc):
    eip_saved=pops(uc,esp)
    uExitcode=pops(uc,esp+4)
    print('0x%0.2x:\tcall ExitProcess(0x%0.2x)' % (eip_saved,uExitcode))
    uc.emu_stop()

'''
	hook GetFileSize(hFile, __out__ lpFileSizeHigh)
'''
def hook_GetFileSize(id,esp,uc):
	eip_saved=pops(uc,esp)
	hFile=pops(uc,esp+4)
	lpFileSizeHigh=pops(esp+8)
	FileSizeHigh=pops(lpFileSizeHigh,4)
	print('0x%0.2x:\tcall GetFileSize(0x%0.2x,lpFileSizeHigh=0x%0.2x)' % (eip_saved,hFile,FileSizeHigh))
	uc.reg_write(UC_X86_REG_ESP,esp+0x08)
	eip_packed=struct.pack('<I',eip_saved)
	uc.mem_write(esp+8,eip_packed)
	#......
'''
hook CreateFileA(lpFileName,dwDesiredAccess, dwShareMode, lpSecurityAttributes, 
                   dwCreationDisposition, dwFlagsAndAttributes, hTemplatteFile )'''
def hook_CreateFileA(id,esp,uc):
	eip_saved=pops(uc,esp)
	lpFileName=pops(uc,esp+4)
	dwCreationDisposition=pops(uc,esp+0x14)
	szFileName=uc.mem_read(lpFileName,0x100)
	FileName=string_pack(szFileName)
	print('0x%0.2x:\tcall CreateFileA(filename=%s,creationDisposition=%s)' % (eip_saved,FileName,CreationDisposition[dwCreationDisposition]))
	uc.reg_write(UC_X86_REG_ESP,esp+0x1c)
	uc.reg_write(UC_X86_REG_EAX,0x69)
	eip_packed=struct.pack('<I',eip_saved)
	uc.mem_write(esp+0x1c,eip_packed)

'''
	hook WriteFile(hFile, lpBuff, nNumberOfBytesWrite, lpNumberOfBytesWritten, lpVerlapped)
'''
def hook_WriteFile(id,esp,uc):
	eip_saved=pops(uc,esp)
	hFile=pops(uc,esp+4)
	lpBuff=pops(uc,esp+8)
	nNumberOfBytesWrite=pops(uc,esp+0x0c)
	lpNumberOfBytesWritten=pops(uc,esp+0x10)
	print('0x%0.2x:\t call WriteFile(hFile=0x%0.2x,lpBuff=0x%0.2x,nNumberOfBytesWrite=0x%0.2x)' % (hFile,lpBuff,nNumberOfBytesWrite))
	uc.reg_write(UC_X86_REG_ESP,esp+0x14)
	uc.reg_write(UC_X86_REG_EAX,0x69)
	eip_packed=struct.pack('<I',eip_saved)
	uc.mem_write(esp+0x14,eip_packed)
	uc.mem_write(lpNumberOfBytesWritten,struct.pack('<I',nNumberOfBytesWrite))
	
'''
	hook ReadFile(hFile, lpBuff, nNumberOfBytesToRead, lpNumberOfBytesRead, lpVerlapped)
'''
def hook_ReadFile(id,esp,uc):
	eip_saved=pops(uc,esp)
	hFile=pops(uc,esp+4)
	lpBuff=pops(uc,esp+8)
	nNumberOfBytesToRead=pops(uc,esp+0x0c)
	lpNumberOfBytesRead=pops(uc,esp+0x10)
	print('0x%0.2x:\t call ReadFile(hFile=0x%0.2x,lpBuff=0x%0.2x,nNumberOfBytesToRead=0x%0.2x)' % (hFile,lpBuff,nNumberOfBytesToRead))
	uc.reg_write(UC_X86_REG_ESP,esp+0x14)
	uc.reg_write(UC_X86_REG_EAX,0x69)
	eip_packed=struct.pack('<I',eip_saved)
	uc.mem_write(esp+0x14,eip_packed)
	uc.mem_write(lpNumberOfBytesRead,struct.pack('<I',nNumberOfBytesToRead))
#using Capstone for diassembly code
def disas(code,address):
    md=Cs(CS_ARCH_X86,CS_MODE_32)
    assem=md.disasm(str(code),address)
    return assem

#hook instruction for Win32 API patching
def hook_code(uc, address, size, user_data):
    # read this instruction code from memory
    code=uc.mem_read(address,size)
    # read register values
    esp=uc.reg_read(UC_X86_REG_ESP)
    eip=uc.reg_read(UC_X86_REG_EIP)
    #code disassembly
    '''asm=disas(code,address)
    for a in asm:
        print ('0x%x: \t%s\t%s' % (a.address, a.mnemonic, a.op_str))'''

    if((eip in imp_des)):
        globals()['hook_'+imp_des[eip]](eip,esp,uc)
def dll_loader(dllName,base):
    module=dllName+'.dll'
    path='dll/'+module
    dll=pefile.PE(path,fast_load=True)
    dll.parse_data_directories()
    data=bytearray(dll.get_memory_mapped_image())
    for entry in dll.DIRECTORY_ENTRY_EXPORT.symbols:
        data[entry.address]='\xc3'
        imp_des[base+entry.address]=entry.name
    return str(data)

#main thread
def main():
    print('\n===Creating Report=======')
    print('Emulate w32Shell Start...')
    try:

        # initialize unicorn emulator
        mu = Uc(UC_ARCH_X86, UC_MODE_32)
        # map 4MB for this emulation
        mu.mem_map(FS, 4 * 1024 * 1024)

        shellcode = input_shellcode()
        # write shellcode to emulation memory
        mu.mem_write(ADDRESS, shellcode)
        # load dll from disk
        kernel32 = dll_loader('kernel32', DLL_BASE)
        kernel32_base = DLL_BASE
        # ntdll_base=DLL_BASE+len(kernel32)
        # ntdll=dll_loader('ntdll')
        mu.mem_write(kernel32_base, kernel32)
        # Initial PEB,TIB,LDR,...
        TIB = FS
        PEB = TIB + 0x30
        LDR = PEB + 0x0C
        InInitOrder = LDR + 0x1C
        BaseName = InInitOrder + 0x20
        # map PEB & LDR Structure to memory
        mu.mem_write(PEB, struct.pack('<i', PEB))
        mu.mem_write(LDR, struct.pack('<i', LDR))
        mu.mem_write(InInitOrder, struct.pack('<i', InInitOrder))
        mu.mem_write(InInitOrder + 8, struct.pack('<i', kernel32_base))
        mu.mem_write(BaseName, struct.pack('<i', BaseName + 4))
        mu.mem_write(BaseName + 4, str(kr32))
        # mu.mem_write(InLoadOrderModuleList,struct.pack('<i',InLoadOrderModuleList))
        # mu.mem_write(InLoadOrderModuleList+4,struct.pack('<i',InLoadOrderModuleList+0x22))
        # mu.mem_write(InLoadOrderModuleList+0x22+0x18,struct.pack('<i',ntdll_base))

        # initialize ESP,EBP register
        mu.reg_write(UC_X86_REG_ESP, ADDRESS + 0x2000)
        mu.reg_write(UC_X86_REG_EBP, ADDRESS + 0x2000)
        mu.reg_write(UC_X86_REG_FS, TIB)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code, None, DLL_BASE, DLL_BASE + 4 * PageSize)
        # mu.hook_add(UC_HOOK_CODE,hook_code1,None,0x4020c,0x4020f)
        mu.emu_start(ADDRESS, ADDRESS + len(shellcode))

        print("Emulation done...")
    except UcError as e:
        print("ERROR: %s" % e)
        mu.emu_stop()
if __name__ == '__main__':
    main()
