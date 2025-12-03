`gcc -shared -fPIC -o truelib.so truelib.c -ldl && LD_PRELOAD=./truelib.so ./Dungeon`
