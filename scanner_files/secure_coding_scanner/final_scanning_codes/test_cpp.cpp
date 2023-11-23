#include <iostream>
#include <cstring>

int main() {
    // Code that matches a rule (Buffer Overflow)
    char buffer[10];
    strcpy(buffer, "This is a long string that might cause a buffer overflow!");

    // Code that matches a rule (Null Pointer Dereference)
    int* nullPointer = nullptr;
    *nullPointer = 42;

    // Code that matches a rule (Use After Free)
    int* dynamicInt = new int;
    delete dynamicInt;
    *dynamicInt = 100;

    // Code that matches a CVE pattern (CVE-2023-1111)
    char input[100];
    scanf("%s", input);

    return 0;
}
