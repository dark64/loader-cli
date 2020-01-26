#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <stdio.h>
#include <string>
#include <TlHelp32.h>

#define RT_ERROR   1
#define RT_SUCCESS 0

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

bool FileExists(const std::string& name) 
{
    if (FILE *file = fopen(name.c_str(), "r")) 
    {
        fclose(file);
        return true;
    }
    return false;
}

int main(int argc, char* argv[])
{
    if (argc <= 2) 
    {
        LOG("Usage: %s [DLL] [PROCESS]", argv[0]);
        return RT_ERROR;
    }

    CHAR path[MAX_PATH];
    DWORD length = GetFullPathName(TEXT(argv[1]), MAX_PATH, path, NULL);

    if (!FileExists(path))
    {
        LOG("Could not find %s\n", path); getchar();
        return RT_ERROR;
    }

    LOG("Searching for %s...\n", argv[2]);
    HANDLE hProcess = NULL;

    do
    {
        hProcess = GetProcessHandle(argv[2]);
        Sleep(100);
    } 
    while (!hProcess);

    LOG("Found %s (at: 0x%x)\n", argv[2], hProcess);
    LPVOID pBuffer = VirtualAllocEx(hProcess, 0, length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hProcess, pBuffer, (LPVOID)path, length, 0);

    LPVOID hLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    if (!CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)hLoadLibrary, pBuffer, 0, 0))
    {
        LOG("Could not create remote thread in target process (%d)\n", GetLastError());
        getchar();
    }

    return RT_SUCCESS;
}