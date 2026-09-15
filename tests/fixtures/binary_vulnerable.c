#include <string.h>

int main(void)
{
    char destination[16];
    const char source[] = "fixture";

    strcpy(destination, source);
    return destination[0] == '\0';
}