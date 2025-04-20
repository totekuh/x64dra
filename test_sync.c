#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>

void hidden_function() {
    puts("[*] Inside hidden_function()");
    Sleep(100);  // debugger breakpoint bait
}

void memory_fiddler() {
    puts("[*] Inside memory_fiddler()");
    char *buf = (char *)malloc(64);
    if (!buf) return;

    strcpy(buf, "testing memory writes...");
    printf("[+] buf = %s\n", buf);

    free(buf);
}

int main() {
    puts("[*] Starting test_sync");

    for (int i = 0; i < 3; i++) {
        printf("[*] Loop %d\n", i);
        Sleep(50);  // simulate work
    }

    hidden_function();
    memory_fiddler();

    puts("[*] Done.");
    return 0;
}
