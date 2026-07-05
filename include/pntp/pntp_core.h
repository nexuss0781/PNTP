#ifndef PNTP_CORE_H
#define PNTP_CORE_H

#include <cstdint>
#include <cstddef>

#define PNTP_ENTROPY_POOL_SIZE 256

extern "C" {
    uint64_t get_rdtsc();
    uint64_t get_rdtsc_serialized();
    void     get_rdtscp(uint32_t* lo, uint32_t* hi, uint32_t* proc_id);
    void     mfence_acquire();
    void     mfence_release();
    void     cache_flush_line(const void* addr);
    void     avx2_copy_nt(void* dst, const void* src, size_t len);
    uint64_t stealth_rand();
    void     init_entropy_pool();
    void     cpuid_string(uint32_t leaf, char* buffer);
    void     pause_loop(uint64_t count);
    void     prefetch_range(const void* addr, size_t len);
    void     generate_stealth_id(char* buffer);
}

#endif // PNTP_CORE_H
