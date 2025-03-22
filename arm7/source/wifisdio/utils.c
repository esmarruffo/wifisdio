#include "wifisdio.h"
#include <stdint.h>

void print_array_hex(char* prefix, uint8_t* array, uint32_t size) {
    print(prefix);
    for(int i = 0; i < size; i++) {
        print("%02X ", array[i]);
    }
    print("\n\n");
}