#include <Windows.h>
#include <stdio.h>
#include <vector>
#include <tlhelp32.h>

using namespace std;

#define  PROCESS_THREAD_ACCESS   PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_READ|PROCESS_VM_WRITE

// Undocumented function and relative structure

// http://securityxploded.com/ntcreatethreadex.php
// Using CreateRemoteThread :
// Terminal Services isolates each terminal session by design. Therefore, CreateRemoteThread fails if the target process is in a different session than the calling process.

typedef NTSTATUS (WINAPI *LPFUN_NtCreateThreadEx) 
(
  OUT PHANDLE hThread,
  IN ACCESS_MASK DesiredAccess,
  IN LPVOID ObjectAttributes,
  IN HANDLE ProcessHandle,
  IN LPTHREAD_START_ROUTINE lpStartAddress,
  IN LPVOID lpParameter,
  IN BOOL CreateSuspended, 
  IN ULONG StackZeroBits,
  IN ULONG SizeOfStackCommit,
  IN ULONG SizeOfStackReserve,
  OUT LPVOID lpBytesBuffer
);

//Buffer argument passed to NtCreateThreadEx function

struct NtCreateThreadExBuffer
{
  ULONG Size;
  ULONG Unknown1;
  ULONG Unknown2;
  PULONG Unknown3;
  ULONG Unknown4;
  ULONG Unknown5;
  ULONG Unknown6;
  PULONG Unknown7;
  ULONG Unknown8;
};


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

    tkp.PrivilegeCount           = 1;
    tkp.Privileges[0].Luid       = luid;
    tkp.Privileges[0].Attributes = 0;
 
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

HANDLE GetHandleModuleInjected( DWORD dwPID, char *szModulePath )
{
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;

	// Take a snapshot of all modules in the specified process.
	hModuleSnap = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, dwPID );
	if( hModuleSnap == INVALID_HANDLE_VALUE )
	{
		printf( "[ERROR] : CreateToolhelp32Snapshot error 0x%08X\n", GetLastError() );
		return hModuleSnap;
	}

	// Set the size of the structure before using it.
	me32.dwSize = sizeof( MODULEENTRY32 );

	// Retrieve information about the first module,
	// and exit if unsuccessful
	if( !Module32First( hModuleSnap, &me32 ) )
	{
		printf( "[ERROR] : Module32First error 0x%08X\n", GetLastError() );  // show cause of failure
		CloseHandle( hModuleSnap );           // clean the snapshot object
		return hModuleSnap;
	}

	// Now walk the module list of the process,
	// and display information about each module
	do
	{
		if( strstr( szModulePath, me32.szModule ) )
		{
			break;
		}
	} 
	while( Module32Next( hModuleSnap, &me32 ) );

	CloseHandle( hModuleSnap );

	return hModuleSnap;
}

void main( int argc, char* argv[] ) 
{
	DWORD    dwPID;
	HANDLE   hThread = NULL;
	NTSTATUS status;

	char    *szDllPath;

	LPVOID pRemoteMem = NULL;

	if( argc < 3 )
	{
		printf( "Usage : %s <PROCESS_NAME> <DLL_PATH>\n", argv[0] );

		return;
	}
	
	szDllPath = argv[2];

	vector<PROCESSENTRY32> ape32ProcessList = GetProcessListExeName( argv[1] );
	if( ape32ProcessList.size() > 0 )
	{
		dwPID = ape32ProcessList[0].th32ProcessID;
	}

	printf( "# Injecting %s in %s (PID %d)\n", szDllPath, argv[1], dwPID );

	SetDebugPrivilege(TRUE);

	// Open remote process
	HANDLE hProcess = OpenProcess( PROCESS_THREAD_ACCESS, FALSE, dwPID );
	if( hProcess == NULL ) 
	{
		printf( "[ERROR] : Can't open process (0x%08X)\n", GetLastError() );

		goto end;
	}

	// Load LoadLibraryA function address
	HMODULE hModule = GetModuleHandle("kernel32.dll");
	if( hModule == NULL )
	{
		printf( "[ERROR] : GetModuleHandle error (0x%08X)\n", GetLastError() );

		goto end;
	}
	
	PTHREAD_START_ROUTINE pThreadRoutine = (PTHREAD_START_ROUTINE)GetProcAddress( hModule, "LoadLibraryA" );
	if( pThreadRoutine == NULL ) 
	{
		printf( "[ERROR] : LoadLibrary not found (0x%08X)\n", GetLastError() );

		goto end;
	}
	
	HMODULE modNtDll = GetModuleHandle("ntdll.dll"); 
	if( modNtDll == NULL ) 
	{
		printf( "[ERROR] : GetModuleHandle error (0x%08X)\n", GetLastError() );

		goto end;
	}

	printf( "# Remote memory Allocation.\n" );

	pRemoteMem = (LPVOID)VirtualAllocEx( hProcess, NULL, strlen(szDllPath), MEM_COMMIT, PAGE_EXECUTE_READWRITE );
	if( pRemoteMem == NULL )
	{
		printf( "[ERROR] : Can't allocate memory (0x%08X)\n", GetLastError() );

		goto end;
	}

	printf( "# Remote memory allocated : 0x%08X\n", pRemoteMem );

	printf( "# Writing remote memory.\n" );

	int n = WriteProcessMemory( hProcess, pRemoteMem, szDllPath, strlen(szDllPath), NULL );
	if( n == 0 )
	{
		printf( "[ERROR] : Can't write on memory process (0x%08X)\n", GetLastError() );

		goto end;
	}

	// 
	// We're using this undocumented func because the simple CreateRemoteThread can't access
	// from a session to another session (session separation)
	//
	LPFUN_NtCreateThreadEx funNtCreateThreadEx = (LPFUN_NtCreateThreadEx) GetProcAddress(modNtDll, "NtCreateThreadEx");

	if( !funNtCreateThreadEx )
	{
		printf( "[ERROR] : can't get function address (0x%08X)", GetLastError() );

		goto end;
	}

	NtCreateThreadExBuffer ntbuffer;

	memset (&ntbuffer,0,sizeof(NtCreateThreadExBuffer));
	DWORD temp1 = 0;
	DWORD temp2 = 0;

	ntbuffer.Size = sizeof(NtCreateThreadExBuffer);
	ntbuffer.Unknown1 = 0x10003;
	ntbuffer.Unknown2 = 0x8;
	ntbuffer.Unknown3 = &temp2;
	ntbuffer.Unknown4 = 0;
	ntbuffer.Unknown5 = 0x10004;
	ntbuffer.Unknown6 = 4;
	ntbuffer.Unknown7 = &temp1;
	ntbuffer.Unknown8 = 0;

	status = 
		funNtCreateThreadEx( 
			&hThread, 
			0x1FFFFF, 
			NULL, 
			hProcess,
			(LPTHREAD_START_ROUTINE) pThreadRoutine,
			pRemoteMem,
			FALSE,
			NULL,
			NULL,
			NULL,
			&ntbuffer
		);


	//ThreadID = CreateRemoteThread( hProcess, NULL, 0, pThreadRoutine, pRemoteMem, NULL, NULL );
	if( hThread == NULL ) 
	{
		printf( "[ERROR] : Can't create remote thread (0x%08X)\n", status );
	}

	DWORD dwInjectedDllBase = 0;

	printf( "[SUCCESS] : the remote thread was successfully created\n" );

	WaitForSingleObject( hThread, INFINITE );
		
	GetExitCodeThread( hProcess, &dwInjectedDllBase );

	CloseHandle(hThread);

end:
	if( pRemoteMem !=  0 )
	{
		VirtualFreeEx( hProcess, pRemoteMem, 0, MEM_RELEASE );
	}
 
	if( hProcess != NULL )
	{
		CloseHandle(hProcess);
	}
 
	return;
}