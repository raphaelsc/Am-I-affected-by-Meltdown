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

#pragma once

// TODO: make it more reusable.
__attribute__((always_inline))
inline void __cpu_id(unsigned& eax, unsigned& ebx, unsigned& ecx) {
    __asm__ __volatile__ ( "movl %%ebx, %%esi\n"
                           "cpuid\n"
                           "movl %%ebx, %0\n"
                           "movl %%esi, %%ebx\n"
                           : "=a"(ebx) : "0" (eax), "c" (ecx) : "esi",
                           "ebx",
                           "edx"
                           );
}

__attribute__((always_inline))
inline void __clflush(const char *address)
{
    asm __volatile__ (
        "mfence         \n"
        "clflush 0(%0)  \n"
        :
        : "r" (address)
        :            );
}

// label defined in asm inline for loading kernel address, which purpose is
// to help with software-based trap mitigation, when TSX isn't available.
extern char __speculative_byte_load_exit[];

inline void __speculative_byte_load(uintptr_t addr, char* dest) {
    asm __volatile__ (
        ".global __speculative_byte_load_exit \n\t"
        "%=:                              \n"
        "xorq %%rax, %%rax                \n"
        "movb (%[addr]), %%al              \n"
        "shlq $0xc, %%rax                 \n"
        "jz %=b                           \n"
        "movq (%[dest], %%rax, 1), %%rbx   \n"
        "__speculative_byte_load_exit:     \n"
        "nop                               \n"
        : 
        :  [addr] "r" (addr), [dest] "r" (dest)
        :  "%rax", "%rbx");
}

__attribute__((always_inline))
inline unsigned long __measure_load_execution(const char *address) {
    volatile unsigned long duration;
    asm __volatile__ (
        "mfence             \n"
        "lfence             \n"
        "rdtsc              \n"
        "lfence             \n"
        "movl %%eax, %%esi  \n"
        "movl (%1), %%eax   \n"
        "lfence             \n"
        "rdtsc              \n"
        "subl %%esi, %%eax  \n"
        "clflush 0(%1)      \n"
        : "=a" (duration)
        : "c" (address)
        :  "%esi", "%edx");
    return duration;
}
