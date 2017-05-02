#include <stdio.h>
#include "shellcode.h"

int main(void){(*(void(*)()) shellcode)();return 0;}
