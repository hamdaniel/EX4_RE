#include <stdio.h>

int main() {
    char input[256];
    printf("Hello from child\n");
    while (fgets(input, sizeof(input), stdin)) {
        printf("You wrote: %s", input);
    }
    return 0;
}
