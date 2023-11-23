#include <stdio.h>
#include <string.h>

int main() {
    char buffer[100];
    char name[50];
    
    // Buffer Overflow Vulnerability
    printf("Enter your name: ");
    gets(name);  // This function is vulnerable to buffer overflow
    printf("Hello, %s!\n", name);

    // Format String Vulnerability
    char input[50];
    printf("Enter a format string: ");
    gets(input);  // This input is used in a format string
    printf(input);

    return 0;
}
