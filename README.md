### x86-64 linux runtime patching library

originally created for the Dungeon Game challenge at the Game Hacking booth BH MEA.

**[Writeup](https://monogr.ph/69323b2dbf05354abcddc061)**

---

```bash
gcc -shared -fPIC -o truelib.so truelib.c -ldl
LD_PRELOAD=./truelib.so ./Dungeon
```

### API
```c
void* get_base()                                          // Get process base address
int hook_function(void *from, void *to)                   // Hook function with inline jump
int patch_bytes(uintptr_t offset, void *data, size_t len) // Patch bytes at offset from base
void hexdump(void *addr, size_t len)                      // Debug helper
```
