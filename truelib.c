#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

#define OFFSET_HEALTH
#define POS_FUNC 0x0000192f
#define FLOAT_DAT 0x00003234

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
        perror("[wow] mprotect failed");
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
    
    fprintf(stderr, "[wow] hooked %p -> %p\n", from, to);
    return 0;
}

int patch_bytes(uintptr_t offset, void *data, size_t len) {
    void *addr = base + offset;
    if (make_writable(addr, len) != 0) {
        return -1;
    }
    memcpy(addr, data, len);
    fprintf(stderr, "[wow] patched %zu bytes at %p\n", len, addr);
    return 0;
}

void hexdump(void *addr, size_t len) {
    unsigned char *p = addr;
    fprintf(stderr, "[wow] %p: ", addr);
    for (size_t i = 0; i < len; i++)
        fprintf(stderr, "%02x ", p[i]);
    fprintf(stderr, "\n");
}

void MY_function() {
    fprintf(stderr, "meow");
}


// void set_pos_hook(float x, float y, void* player_struct) {
//     ((void (*)(float, float, void*))(base + FUNC))(100.0f, 100.0f, player_struct);
// }

__attribute__((constructor))
void init() {
    page_size = sysconf(_SC_PAGESIZE);
    base = get_base();


    fprintf(stderr, "[wow] base: %p\n", base);
    // hook_function(base + POS_FUNC, set_pos_hook);
    // unsigned char ins[] = {
    //     0xc7, 0x40, 0x20, 0xFF, 0x00, 0x00, 0x00 // MOV [RAX + 0x20],0x64
    // };

    
    float val = 400.0f;
    patch_bytes(FLOAT_DAT, &val, sizeof(val));
    // ((void (*)(void))(base + POS_FUNC))();


}

// ((void (*)(void))(base + FUNC_ADDRESS))();

// unsigned char nops[] = {0x90, 0x90, 0x90, 0x90, 0x90};

// mov eax, 224 = B8 E0 00 00 00
// mov eax, 400 = 90 01 00 00 00

// unsigned char mov_eax[] = {0xB8, 0xE0};
// do enough to cover the old ins

// patch_bytes(offset1, nops, sizeof(nops)); 
// patch_bytes(offset2, nops, sizeof(nops));
// patch_bytes(offse, mov_eax_224, 5);

// unsigned char patch[] = {
//     0xB8, 0x64, 0x00, 0x00, 0x00,  // MOV EAX, 100 5b
//     0x90, 0x90                      // NOP NOP      2b
// };

__attribute__((destructor))
void cleanup(void) {
    fprintf(stderr, "\n[wow] cleanup\n");
}

static int (*original_rand)(void) = NULL;

int rand(void) {
    if (!original_rand) {
        original_rand = dlsym(RTLD_NEXT, "rand");
    }
    return RAND_MAX;
}