#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

static void *base = NULL; 
static size_t page_size = 0;

void* get_base() {
    FILE *f = fopen("/proc/self/maps", "r");
    void *base = NULL;
    char line[512];
    
    if (fgets(line, sizeof(line), f)) {
        sscanf(line, "%p", &base);
    }

    fclose(f);
    return base;
}

int make_writable(void *addr, size_t len) {
    void *page = (void *)((uintptr_t)addr & ~(page_size - 1));
    if (mprotect(page, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        perror("[TRUEE] mprotect failed");
        return -1;
    }
    return 0;
}

int hook_function(void *from, void *to) {
    if (make_writable(from, 12) != 0) {
        return -1;
    }
    
    unsigned char jump[] = {
        0x48, 0xB8, 0,0,0,0,0,0,0,0,  // movabs rax, imm64
        0xFF, 0xE0                    // jmp rax
    };
    memcpy(&jump[2], &to, 8);
    memcpy(from, jump, sizeof(jump));
    
    fprintf(stderr, "[TRUEE] hooked %p -> %p\n", from, to);
    return 0;
}

int patch_bytes(uintptr_t offset, void *data, size_t len) {
    void *addr = base + offset;
    if (make_writable(addr, len) != 0) {
        return -1;
    }
    memcpy(addr, data, len);
    fprintf(stderr, "[TRUEE] patched %zu bytes at %p\n", len, addr);
    return 0;
}

void hexdump(void *addr, size_t len) {
    unsigned char *p = addr;
    fprintf(stderr, "[TRUEE] %p: ", addr);
    for (size_t i = 0; i < len; i++)
        fprintf(stderr, "%02x ", p[i]);
    fprintf(stderr, "\n");
}

__attribute__((constructor))
void init() {
    page_size = sysconf(_SC_PAGESIZE);
    base = get_base();


    fprintf(stderr, "[TRUEE] base: %p\n", base);
    // addr = base + offset
    // some funcs require addr some just offset because yeah

    
    // patch_bytes(FLOAT_DAT, &val, sizeof(val));
}

// ((void (*)(void))(base + FUNC_ADDRESS))();

// unsigned char nops[] = {0x90, 0x90, 0x90, 0x90, 0x90};

// mov eax, 224 = B8 E0 00 00 00
// mov eax, 400 = 90 01 00 00 00

// unsigned char patch[] = {
//     0xB8, 0x64, 0x00, 0x00, 0x00,  // MOV EAX, 100 5b
//     0x90, 0x90                      // NOP NOP      2b
// };

__attribute__((destructor))
void cleanup(void) {
    fprintf(stderr, "\n[TRUEE] cleanup\n");
}



// static int (*original_rand)(void) = NULL;

// int rand(void) {
//     if (!original_rand) {
//         original_rand = dlsym(RTLD_NEXT, "rand");
//     }
//     return RAND_MAX;
// }
