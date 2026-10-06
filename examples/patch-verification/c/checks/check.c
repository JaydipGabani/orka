#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int accept_quantity(int quantity);

int main(int argc, char **argv) {
    if (argc != 2 || (strcmp(argv[1], "5") && strcmp(argv[1], "-1") && strcmp(argv[1], "101"))) {
        return 125;
    }
    int quantity = atoi(argv[1]);
    int expected = quantity == 5;
    puts(accept_quantity(quantity) == expected ? "healthy" : "broken");
    return 0;
}
