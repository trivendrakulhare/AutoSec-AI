#include <string.h>

int main(void)
{
    char destination[16];
    const char source[] = "fixture";

    memcpy(destination, source, sizeof(source));
    return destination[0] == '\0';
}