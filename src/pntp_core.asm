section .note.GNU-stack noalloc noexec nowrite progbits

section .data
    entropy_pool: times 256 db 0
    pool_initialized: db 0

section .text
    CPU x86-64
    global get_rdtsc
    global get_rdtsc_serialized
    global get_rdtscp
    global mfence_acquire
    global mfence_release
    global cache_flush_line
    global avx2_copy_nt
    global stealth_rand
    global init_entropy_pool
    global cpuid_string
    global pause_loop
    global prefetch_range
    global generate_stealth_id

; uint64_t get_rdtsc()
; Returns the processor's time-stamp counter (TSC) — no serialization.
get_rdtsc:
    rdtsc
    shl rdx, 32
    or rax, rdx
    ret

; uint64_t get_rdtsc_serialized()
; Fully serialized RDTSC with memory barrier and instruction barrier.
get_rdtsc_serialized:
    mfence
    lfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    ret

; void get_rdtscp(uint32_t* lo, uint32_t* hi, uint32_t* proc_id)
; rdi = lo output, rsi = hi output, rdx = proc_id output
get_rdtscp:
    rdtscp
    test rdi, rdi
    jz .skip_lo
    mov [rdi], eax
.skip_lo:
    test rsi, rsi
    jz .skip_hi
    mov [rsi], edx
.skip_hi:
    test rdx, rdx
    jz .skip_proc
    mov [rdx], ecx
.skip_proc:
    ret

; void mfence_acquire()
; Memory barrier — acquire semantics.
mfence_acquire:
    mfence
    ret

; void mfence_release()
; Memory barrier — release semantics.
mfence_release:
    mfence
    ret

; void cache_flush_line(const void* addr)
; Flush cache line containing addr from all cache levels.
cache_flush_line:
    clflush [rdi]
    sfence
    ret

; void avx2_copy_nt(void* dst, const void* src, size_t len)
; Non-temporal aligned copy using AVX2. Requires 32-byte alignment.
avx2_copy_nt:
    test rdx, rdx
    jz .done
.loop:
    vmovntdqa ymm0, [rsi]
    vmovntdq  [rdi], ymm0
    add rsi, 32
    add rdi, 32
    sub rdx, 32
    jg .loop
    sfence
    vzeroupper
.done:
    ret

; uint64_t stealth_rand()
; Hardware-backed PRNG: RDRAND with entropy-pool fallback.
stealth_rand:
    rdrand rax
    jc .have_val
    xor rax, rax
.have_val:
    push rcx
    push rdx
    rdtsc
    movzx ecx, al
    and ecx, 0xFF
    lea rsi, [entropy_pool]
    movzx ecx, byte [rsi + rcx]
    xor al, cl
    lea rsi, [entropy_pool + 128]
    movzx ecx, byte [rsi + rcx]
    xor ah, cl
    pop rdx
    pop rcx
    ret

; void init_entropy_pool()
; Seeds the 256-byte entropy pool from CPUID leaves and RDRAND.
init_entropy_pool:
    push rbx
    push rcx
    push rdx
    push rdi
    push rsi

    lea rdi, [entropy_pool]
    xor rcx, rcx

.seed_loop:
    rdrand eax
    jnc .use_cpuid
    mov [rdi + rcx], al
    jmp .next
.use_cpuid:
    mov eax, 1
    cpuid
    mov [rdi + rcx], al
.next:
    inc rcx
    cmp rcx, 256
    jb .seed_loop

    mov byte [pool_initialized], 1

    pop rsi
    pop rdi
    pop rdx
    pop rcx
    pop rbx
    ret

; void cpuid_string(uint32_t leaf, char* buffer)
; Dumps full CPUID leaf (eax, ebx, ecx, edx) as 16 bytes into buffer.
cpuid_string:
    push rbx
    push rcx
    push rdx

    mov eax, edi
    xor ecx, ecx
    cpuid
    mov [rsi], eax
    mov [rsi + 4], ebx
    mov [rsi + 8], ecx
    mov [rsi + 12], edx

    pop rdx
    pop rcx
    pop rbx
    ret

; void pause_loop(uint64_t count)
; Spin-loop with PAUSE hints for hyper-threading friendly waiting.
pause_loop:
    test rdi, rdi
    jz .done
.loop:
    pause
    dec rdi
    jnz .loop
.done:
    ret

; void prefetch_range(const void* addr, size_t len)
; Software prefetch for cache warming.
prefetch_range:
    test rsi, rsi
    jz .done
.loop:
    prefetcht0 [rdi]
    add rdi, 64
    sub rsi, 64
    jg .loop
.done:
    ret

; void generate_stealth_id(char* buffer)
; Generates a hardware-level stealth signature using CPUID and TSC.
generate_stealth_id:
    push rbx
    push rcx
    push rdx

    rdtsc
    mov [rdi], eax
    mov [rdi+4], edx

    mov eax, 1
    cpuid
    mov [rdi+8], eax
    mov [rdi+12], ebx

    pop rdx
    pop rcx
    pop rbx
    ret
