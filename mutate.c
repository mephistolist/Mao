#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/utsname.h> 
#include <dlfcn.h>
#include <x86intrin.h>
#include <elf.h>
#include <errno.h>
#include <pthread.h>
#include <cpuid.h>

#define MAX_LEN 128
#define PATH_MAX 200

static unsigned long long internal_seed = 0;

// Prototypes
void mutate1(char *s);
void mutate2(char *s);
void mutate3(char *s);
void mutate4(char *s);
void mutate5(char *s);
void mutate6(char *s);
void mutate7(char *s);
void mutate8(char *s);
void junk_memory(void);
unsigned char internal_random_byte(void);
void shuffle(void (**funcs)(char *), int count);
void obscure_memory_presence(void);
void temporal_obfuscation(void);
void obscure_system_calls(void);

void *background_entropy(void *arg) {
    (void)arg;
    while (1) {
        junk_memory();
        usleep(100000 + (internal_random_byte() % 100000));
    }
    return NULL;
}

void execute_mutations(char *s, void (**mutators)(char *), int count) {
    void (*dispatch[6])(char *) = {0};
    for (int i = 0; i < count; ++i) {
        dispatch[i] = mutators[i];
    }
    shuffle(dispatch, count);
    for (int i = 0; i < count; ++i) {
        dispatch[i](s);
    }
}

void patch_mutator(void (*func)(char *)) {
    unsigned char *target = (unsigned char *)(uintptr_t)func;

    uintptr_t page_start = (uintptr_t)target & ~(sysconf(_SC_PAGE_SIZE) - 1);
    if (mprotect((void *)page_start, sysconf(_SC_PAGE_SIZE), PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        perror("mprotect");
        return;
    }

    // Overwrite up to 16 bytes with NOPs
    for (int i = 0; i < 16; ++i) {
        target[i] = 0x90; // NOP
    }

    // Replace the first instruction with RET
    target[0] = 0xC3;

    // Restore protection
    if (mprotect((void *)page_start, sysconf(_SC_PAGE_SIZE), PROT_READ | PROT_EXEC) != 0) {
        perror("mprotect restore");
    }
}

void init_entropy() {
    unsigned long long t = __rdtsc();
    unsigned long long a = (unsigned long long)&t;
    unsigned long long b = (unsigned long long)time(NULL);
    unsigned long long c = (unsigned long long)getpid();
    unsigned long long d = (unsigned long long)syscall(SYS_gettid);
    
    struct timeval tv;
    gettimeofday(&tv, NULL);
    unsigned long long e = (unsigned long long)tv.tv_usec;
    
    // Add memory layout entropy
    void *stack_var;
    unsigned long long f = (unsigned long long)&stack_var;
    
    // Add CPU-specific entropy
    unsigned int cpu_info[4];
    __cpuid(0, cpu_info[0], cpu_info[1], cpu_info[2], cpu_info[3]);
    unsigned long long g = (unsigned long long)cpu_info[0] << 32 | cpu_info[1];
    
    internal_seed = (t ^ a ^ b ^ c ^ d ^ e ^ f ^ g) * 0x5DEECE66DULL + 0xB;
}

unsigned char internal_random_byte() {
    internal_seed ^= internal_seed >> 21;
    internal_seed ^= internal_seed << 35;
    internal_seed ^= internal_seed >> 4;
    internal_seed *= 2685821657736338717ULL;
    return (unsigned char)(internal_seed >> 56);
}

void get_entropy(unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        buf[i] = internal_random_byte();
    }
}

// Add memory obfuscation techniques
void obscure_memory_presence() {
    // Allocate and immediately free memory to create fragmentation
    for (int i = 0; i < 10; i++) {
        size_t size = 64 + (internal_random_byte() % 1024);
        char *temp = malloc(size);
        if (temp) {
            get_entropy((unsigned char *)temp, size);
            free(temp);
        }
    }
    
    // Create memory artifacts that look like normal program behavior
    int *dummy_array = malloc(256 * sizeof(int));  // Remove volatile
    if (dummy_array) {
        for (int i = 0; i < 256; i++) {
            dummy_array[i] = internal_random_byte();
        }
        free(dummy_array);
    }
}

void temporal_obfuscation() {
    // Random delays to break timing analysis
    unsigned char delay_ms;
    get_entropy(&delay_ms, 1);
    usleep(delay_ms * 1000);
    
    // Insert CPU-intensive but meaningless operations
    volatile unsigned long long counter = 0;
    for (int i = 0; i < 1000 + (internal_random_byte() % 9000); i++) {
        counter += i * internal_random_byte();
    }
    (void)counter;
}

void obscure_system_calls() {
    // Make benign system calls to hide among normal activity
    struct timespec ts = {0, 1000}; // 1 microsecond
    nanosleep(&ts, NULL);
    
    // Check environment variables (common benign activity)
    volatile char *path = getenv("PATH");
    (void)path;
    
    // Get system information
    struct utsname name;
    uname(&name);
}

// Mutation Functions (unchanged)
void mutate1(char *s) {
    size_t len = strlen(s);
    for (size_t i = 0; i < len / 2; ++i) {
        char tmp = s[i];
        s[i] = s[len - i - 1];
        s[len - i - 1] = tmp;
    }
}

void mutate2(char *s) {
    for (size_t i = 0; s[i]; ++i) {
        if ((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z')) {
            s[i]++;
	}
    }
}

void mutate3(char *s) {
    unsigned char key[1];
    get_entropy(key, 1);
    for (size_t i = 0; s[i]; ++i) {
        s[i] ^= key[0];
    }
}

void mutate4(char *s) {
    size_t len = strlen(s);
    for (size_t i = 0; i < len; i++) {
        if (i % 2 == 0)
            s[i] = (s[i] ^ internal_random_byte()) & 0x7F;
    }
}

void mutate5(char *s) {
    unsigned char junk = internal_random_byte() % 94 + 33;
    size_t len = strlen(s);
    if (len > 1) {
        s[internal_random_byte() % len] = junk;
    }
}

void mutate6(char *s) {
    size_t len = strlen(s);
    for (size_t i = 0; i < len; i++) {
        if (internal_random_byte() % 3 == 0) {
            s[i] = s[i] ^ (char)(internal_random_byte() % 64);
	}
    }
}

void mutate7(char *s) {
    // String length obfuscation
    size_t len = strlen(s);
    if (len > 2) {
        // Insert random bytes that look like UTF-8 or other encodings
        s[internal_random_byte() % len] = 0xC0 + (internal_random_byte() % 0x20);
    }
}

void mutate8(char *s) {
    // Heap-like memory pattern insertion
    size_t len = strlen(s);
    if (len > 10) {
        // Insert patterns that look like heap metadata
        memcpy(s + (internal_random_byte() % (len - 8)), "\xef\xbe\xad\xde", 4);
    }
}

void shuffle(void (**funcs)(char *), int count) {
    for (int i = count - 1; i > 0; --i) {
        unsigned char r[1];
        get_entropy(r, 1);
        int j = r[0] % (i + 1);
        void (*tmp)(char *) = funcs[i];
        funcs[i] = funcs[j];
        funcs[j] = tmp;
    }
}

int run_jit_code() {
    size_t pagesize = sysconf(_SC_PAGE_SIZE);
    
    // Randomize allocation size and alignment
    size_t alloc_size = pagesize * (1 + (internal_random_byte() % 3));
    unsigned char *mem = mmap(NULL, alloc_size,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (mem == MAP_FAILED) { return -1; }
    
    // Fill with polymorphic junk patterns
    for (size_t i = 0; i < alloc_size; ++i) {
        mem[i] = internal_random_byte();
        
        // Insert realistic-looking x86 opcode patterns occasionally
        if (internal_random_byte() % 100 < 5) {
            static const unsigned char common_ops[] = {
                0x90, 0xC3, 0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC
            };
            mem[i] = common_ops[internal_random_byte() % sizeof(common_ops)];
        }
    }
    
    // Multiple code fragments with different entry points
    size_t num_fragments = 2 + (internal_random_byte() % 3);
    size_t offsets[5] = {0};
    
    for (size_t frag = 0; frag < num_fragments; frag++) {
        offsets[frag] = (internal_random_byte() % (alloc_size - 64));
        size_t offset = offsets[frag];
        
        // Add polymorphic prologue
        int prologue_size = internal_random_byte() % 8;
        for (int i = 0; i < prologue_size; i++) {
            mem[offset++] = 0x90; // NOP
        }
        
        // Generate different types of code fragments
        if (internal_random_byte() % 2 == 0) {
            // Math operation fragment
            unsigned char math_ops[] = {
                0x48, 0x83, 0xC0, internal_random_byte(), // add $val, %rax
                0x48, 0x83, 0xE8, internal_random_byte(), // sub $val, %rax
                0x48, 0x31, 0xC0,                         // xor %rax, %rax
            };
            memcpy(mem + offset, math_ops, sizeof(math_ops));
            offset += sizeof(math_ops);
        } else {
            // Memory operation fragment
            unsigned char mem_ops[] = {
                0x48, 0x8B, 0x45, 0x00,                   // mov 0x0(%rbp), %rax
                0x48, 0x89, 0x45, 0x08,                   // mov %rax, 0x8(%rbp)
            };
            memcpy(mem + offset, mem_ops, sizeof(mem_ops));
            offset += sizeof(mem_ops);
        }
        
        // Add random junk between fragments
        int junk_size = internal_random_byte() % 16;
        for (int i = 0; i < junk_size; i++) {
            mem[offset++] = internal_random_byte();
        }
    }
    
    // Main function at a random offset
    size_t main_offset = offsets[internal_random_byte() % num_fragments];
    unsigned char random_val;
    get_entropy(&random_val, 1);
    
    unsigned char program[] = {
        0x55,                               // push %rbp
        0x48, 0x89, 0xE5,                   // mov %rsp, %rbp
        0xB8, random_val, 0x00, 0x00, 0x00, // mov $val, %eax
        0x5D,                               // pop %rbp
        0xC3                                // ret
    };
    
    memcpy(mem + main_offset, program, sizeof(program));
    
    // Execute from random entry point
    int (*func)() = (int (*)())(uintptr_t)(mem + main_offset);
    int result = func();
    
    // Advanced memory wiping
    for (size_t i = 0; i < alloc_size; ++i) {
        // Multiple overwrite passes with different patterns
        mem[i] = internal_random_byte();
        if (i % 2 == 0) mem[i] = ~mem[i];
        if (i % 3 == 0) mem[i] = mem[i] ^ 0xAA;
    }
    
    // Remove execute permission before freeing
    mprotect(mem, alloc_size, PROT_NONE);
    munmap(mem, alloc_size);
    
    return result;
}

void junk_memory() {
    size_t allocs = 5 + (internal_random_byte() % 5);
    for (size_t i = 0; i < allocs; ++i) {
        size_t size = 512 + (internal_random_byte() % 1024);
        char *buf = malloc(size);
        if (!buf) { continue; }
        for (size_t j = 0; j < size; ++j) {
            buf[j] = internal_random_byte();
	}
        volatile char dummy = buf[internal_random_byte() % size];
        (void)dummy;
        free(buf);
    }
}

void polymorphic_junk() {
    unsigned char r = internal_random_byte();
    for (int i = 0; i < (r % 5) + 1; ++i) {
        asm volatile (
            "nop\n\t"
            "xor %%eax, %%eax\n\t"
            "add $0x1, %%eax\n\t"
            :
            :
            : "eax"
        );
    }
}

void (*all_mutators[])(char *) = {
    mutate1, mutate2, mutate3, mutate4, mutate5, mutate6, mutate7, mutate8
};

int mutate_main() {
    init_entropy();
    srand(internal_seed ^ __rdtsc());

    // Start background entropy thread
    pthread_t tid;
    pthread_create(&tid, NULL, background_entropy, NULL);

    polymorphic_junk();
    junk_memory();

    // Call function to overwrite mutate functions with NOPS
    int num_mutators = sizeof(all_mutators) / sizeof(all_mutators[0]);
    for (int i = 0; i < num_mutators; ++i) {
    	patch_mutator(all_mutators[i]);
    }

    char input[MAX_LEN];
    unsigned char len_byte;
    get_entropy(&len_byte, 1);
    int len = 5 + (len_byte % (MAX_LEN - 6));
    for (int i = 0; i < len; ++i) {
        unsigned char c;
        get_entropy(&c, 1);
        input[i] = 33 + (c % 94); // printable ASCII
    }
    input[len] = '\0';

    char mutated[MAX_LEN];
    strcpy(mutated, input);
    //printf("Original: %s\n", input);

    void (*mutators[])(char *) = {
        mutate1, mutate2, mutate3, mutate4, mutate5, mutate6, mutate7, mutate8
    };
    int mut_count = sizeof(mutators) / sizeof(mutators[0]);
    shuffle(mutators, mut_count);

    unsigned char passes = 2 + (internal_random_byte() % 4); // 2 to 5 passes
    for (int i = 0; i < passes; ++i) {
        mutators[i % mut_count](mutated);
    }
    //printf("Mutated : %s\n", mutated);

    int val = run_jit_code();
    (void)val;
    //printf("JIT Code Result: %d\n", val);
    
    obscure_memory_presence();
    obscure_system_calls();
    temporal_obfuscation();

    return 0;
}
