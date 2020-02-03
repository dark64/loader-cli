#pragma warning( disable : 6387 )

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <stdio.h>
#include <string>
#include <TlHelp32.h>

#define LOG(...) printf_s(__VA_ARGS__)

HANDLE GetProcessHandle(const char* pName)
{
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hProcess = NULL;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (hSnapshot == INVALID_HANDLE_VALUE || hSnapshot == NULL)
        return NULL;

    if (!Process32First(hSnapshot, &entry))
    {
        CloseHandle(hSnapshot);
        return NULL;
    }

    do
    {
        if (!_strcmpi(entry.szExeFile, pName))
        {
            hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
            break;
        }
    } 
    while (Process32Next(hSnapshot, &entry));

    CloseHandle(hSnapshot);
    return hProcess;
}

LPCSTR GetFileName(LPCSTR base)
{
    LPCSTR filename = base;
    for (int i = strlen(base) - 1; i >= 0; i--)
    {
        if (base[i] == '\\') {
            filename = base + i + 1;
            break;
        }
    }
    return filename;
}

BOOL FileExists(LPCSTR filePath) 
{
    if (FILE *file = fopen(filePath, "r"))
    {
        fclose(file);
        return TRUE;
    }
    return FALSE;
}

int main(int argc, char* argv[])
{
    if (argc < 3) 
    {
        LOG("Usage: %s [DLL] [PROCESS]", GetFileName(argv[0]));
        return EXIT_FAILURE;
    }

    CHAR path[MAX_PATH];
    DWORD length = GetFullPathName(TEXT(argv[1]), MAX_PATH, path, NULL);

    if (!FileExists(path))
    {
        LOG("Could not find %s\n", path);
        return EXIT_FAILURE;
    }

    LOG("Searching for %s...\n", argv[2]);
    HANDLE hProcess = NULL;

    do
    {
        hProcess = GetProcessHandle(argv[2]);
        Sleep(100);
    } 
    while (!hProcess);

    LOG("Found %s (at: 0x%x)\n", argv[2], (DWORD)hProcess);
    LPVOID pBuffer = VirtualAllocEx(hProcess, 0, length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hProcess, pBuffer, (LPVOID)path, length, 0);

    LPVOID hLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    if (!CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)hLoadLibrary, pBuffer, 0, 0))
    {
        LOG("Could not create remote thread in target process (%d)\n", GetLastError());
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    CloseHandle(hProcess);
    return EXIT_SUCCESS;
}
