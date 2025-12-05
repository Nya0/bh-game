x86-64 linux runtime patching library

originally for the Dungeon Game challenge at the Game Hacking booth in bh mea

- `gcc -shared -fPIC -o truelib.so truelib.c -ldl && LD_PRELOAD=./truelib.so ./Dungeon`


```c
void* get_base()                                             // get process base address
int hook_function(void *from, void *to)                      // hook function with inline jump
int patch_bytes(uintptr_t offset, void *data, size_t len)    // patch bytes at offset from base
void hexdump(void *addr, size_t len)                         // debug helper
```

