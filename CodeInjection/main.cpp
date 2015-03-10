#include <stdio.h>
#include <Windows.h>
#include <vector>
#include <tlhelp32.h>

#pragma comment(lib,"ntdll.lib")

using namespace std;


void WINAPI ThreadProc( HINSTANCE hInst )
{
	MessageBox( 0, "Hello", "Welcome Message",1 );

	ExitThread(0);
}

bool IsWindowsNT( )
{
    return ( GetVersion() < 0x80000000 ) ? true : false;
}

vector<PROCESSENTRY32> GetProcessListExeName( PCSTR szExeName )
{
    HANDLE                  hSnapProcess      = NULL;
    PROCESSENTRY32          pe32              = {0};
    vector<PROCESSENTRY32>  ape32ProcessList;
 
    if( !IsWindowsNT( ) || !szExeName )
        return ape32ProcessList;
 
 
    if( !( hSnapProcess = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 ) ) )
        return ape32ProcessList;
 
    pe32.dwSize = sizeof( PROCESSENTRY32 );
    if( Process32First( hSnapProcess, &pe32 ) )
    {
        do
        {
            if( strcmp( pe32.szExeFile, szExeName ) == 0 )
            {
                ape32ProcessList.push_back( pe32 );
            }
        } 
		while( Process32Next( hSnapProcess, &pe32 ) );
    }
 
    CloseHandle(hSnapProcess);
 
    return ape32ProcessList;
}


BOOL SetPrivilege(
    HANDLE  hToken,
    LPCTSTR lpPrivilege,
    BOOL    bEnablePrivilege
)
{
    // Initializing variables
    TOKEN_PRIVILEGES    tkp         = {0};
    LUID                luid        = {0};
    TOKEN_PRIVILEGES    tkpPrevious = {0};
    DWORD               cbPrevious  =  0;
 
    // Check the parameters passed to the function
    if( ( !hToken ) || ( !lpPrivilege ) )
	{
        return FALSE;
	}
 
    if( !LookupPrivilegeValue( NULL, lpPrivilege, &luid ) )
	{
        return FALSE;
	}

    tkp.PrivilegeCount            = 1;
    tkp.Privileges[0].Luid        = luid;
    tkp.Privileges[0].Attributes  = 0;
 
    cbPrevious = sizeof( TOKEN_PRIVILEGES );
    AdjustTokenPrivileges( hToken, FALSE, &tkp, sizeof( TOKEN_PRIVILEGES ), &tkpPrevious, &cbPrevious );
    if( GetLastError() != ERROR_SUCCESS )
	{
        return FALSE;
	}
 
    tkpPrevious.PrivilegeCount      = 1;
    tkpPrevious.Privileges[0].Luid  = luid;

    if( bEnablePrivilege )
	{
        tkpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
	}
    else
	{
        tkpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED & tkpPrevious.Privileges[0].Attributes);
	}
 
    AdjustTokenPrivileges( hToken, FALSE, &tkpPrevious, cbPrevious, NULL, NULL );
    if( GetLastError() != ERROR_SUCCESS )
	{
        return FALSE;
	}
 
    return TRUE;
}

 
//
//  Set debug privilege
//
BOOL SetDebugPrivilege( BOOL bEnable )
{
    HANDLE hToken = NULL;
 
    if( !OpenProcessToken( GetCurrentProcess( ), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken ) )
        return FALSE;
 
    // Enable/Disable Debug Privilege
    if( !SetPrivilege( hToken, SE_DEBUG_NAME, bEnable ) )
    {
        CloseHandle(hToken);
        
		return FALSE;
    }
 
    CloseHandle(hToken);
 
    return TRUE;
}

void main( int argc, char* argv[] )
{
	PIMAGE_DOS_HEADER      pImageDosHeader;
	PIMAGE_NT_HEADERS      pImageHeaders;
	PIMAGE_DATA_DIRECTORY  pImageDataDirectory;
	PIMAGE_BASE_RELOCATION pImageBaseRelocation;

	HMODULE hModule;
	HANDLE  hProcess, hThread;

	LPVOID pRemoteMem   = NULL;
	LPVOID pImage       = NULL;
	PVOID  StartAddress = NULL;
	
	DWORD dwSizeOfImage;
	DWORD dwPID;
	DWORD dwCount;

	DWORD_PTR delta, OldDelta;

	LPWORD     list;
	PDWORD_PTR p;

	if( argc != 2 )
	{
		printf( "Usage : %s <PROCESS_NAME>\n", argv[0] );

		return;
	}

	vector<PROCESSENTRY32> ape32ProcessList = GetProcessListExeName( argv[1] );
	if( ape32ProcessList.size() > 0 )
	{
		dwPID = ape32ProcessList[0].th32ProcessID;
	}

	SetDebugPrivilege(TRUE);

	hModule = GetModuleHandle(NULL);
	if( hModule == NULL )
	{
		printf("[ERROR] : GetModuleHandle failed with status 0x%08X\n", GetLastError() );
		
		return;
	}

	pImageDosHeader = (PIMAGE_DOS_HEADER)hModule;

	pImageHeaders = (PIMAGE_NT_HEADERS)( (BYTE*)pImageDosHeader + pImageDosHeader->e_lfanew );

	dwSizeOfImage = pImageHeaders->OptionalHeader.SizeOfImage;

	printf( "# Open Target PID : %d %d\n", dwPID, dwSizeOfImage );
	
	hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, dwPID );
	if( hProcess == NULL )
	{
		printf("[ERROR] : OpenProcess failed with status 0x%08X\n", GetLastError() );
		
		return;
	}

	pRemoteMem = VirtualAllocEx( hProcess, NULL, dwSizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );

	if( pRemoteMem == NULL )
	{
		printf("[ERROR] : VirtualAllocEx failed with error 0x%08X\n", GetLastError() );

		goto end;
	}

	printf( "# Remote Memory allocated : 0x%08X\n", pRemoteMem );

	pImage = VirtualAlloc( NULL, dwSizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );

	memcpy( pImage, hModule, dwSizeOfImage );

	pImageDataDirectory  = &pImageHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	pImageBaseRelocation = (PIMAGE_BASE_RELOCATION)( (LPBYTE)pImage + pImageDataDirectory->VirtualAddress );

	delta    = (DWORD_PTR)( (LPBYTE)pRemoteMem - pImageHeaders->OptionalHeader.ImageBase );
	OldDelta = (DWORD_PTR)( (LPBYTE)hModule - pImageHeaders->OptionalHeader.ImageBase );

	while( pImageBaseRelocation->VirtualAddress != 0 )
	{
		if( pImageBaseRelocation->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION) )
		{
			dwCount = ( pImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) ) / sizeof(WORD);
			list    = (LPWORD)( (LPBYTE)pImageBaseRelocation + sizeof(IMAGE_BASE_RELOCATION) );

			for( unsigned int i = 0; i < dwCount; i++ )
			{
				if( list[i] > 0 )
				{
					p = (PDWORD_PTR)( (LPBYTE)pImage + ( pImageBaseRelocation->VirtualAddress + ( 0x0fff & (list[i]) ) ) );

				   *p -= OldDelta;
				   *p += delta;
				}
			}
		}

		pImageBaseRelocation = (PIMAGE_BASE_RELOCATION)( (LPBYTE) pImageBaseRelocation + pImageBaseRelocation->SizeOfBlock );
	}

	printf("# Writing the image into target process.\n");

	int n = WriteProcessMemory( hProcess, pRemoteMem, pImage, dwSizeOfImage, NULL );
	if( n == 0 )
	{
		printf( "[ERROR] : NtWriteVirtualMemory failed with status 0x%08X\n", GetLastError() );

		goto end;
	}

	StartAddress = (PVOID)( (LPBYTE)pRemoteMem + (DWORD_PTR)(LPBYTE)ThreadProc - (LPBYTE)hModule );

	printf("# Creating remote thread.\n");

	hThread = CreateRemoteThread( hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)StartAddress, pRemoteMem, NULL, NULL );
	if( hThread == NULL ) 
	{
		printf( "[ERROR] : Can't create remote thread (0x%08X)\n", GetLastError() );

		goto end;
	}
	

	printf( "[SUCCESS] : the remote thread was successfully created\n" );

	WaitForSingleObject( hThread, INFINITE );

	CloseHandle(hThread);

end:

	printf("# Freeing memory and handles.\n");

	if( pRemoteMem )
	{
		VirtualFreeEx( hProcess, pRemoteMem, 0, MEM_RELEASE );
	}
	
	if( hProcess )
	{
		CloseHandle(hProcess);
	}

	if( pImage )
	{
		VirtualFree( pImage, 0, MEM_RELEASE );
	}

	return;
}
