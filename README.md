# C-hashing-library
C hashing library providing 6 hashing functions and one bonus:
- `SHA-224`
- `SHA-256`
- `SHA-0`
- `SHA-1`
- `MD-4`
- `MD-5`
- `ROT-13`

## Usage Example
```c
#include <stdio.h>
#include "hashing.h"

int main(int argc, const char *argv[]) {

    if (argc != 2) {
        printf("Provide exactly one argument!\n");
        return 1;
    }

    printf("SHA_224 Hash: %s\n", Hashing.sha_224(argv[1]));
    printf("SHA_256 Hash: %s\n", Hashing.sha_256(argv[1]));
    printf("SHA_0 Hash: %s\n", Hashing.sha_0(argv[1]));
    printf("SHA_1 Hash: %s\n", Hashing.sha_1(argv[1]));
    printf("MD_4 Hash: %s\n", Hashing.md_4(argv[1]));
    printf("MD_5 Hash: %s\n", Hashing.md_5(argv[1]));
    printf("ROT_13 Hash: %s\n", Hashing.rot_13(argv[1]));

    return 0;
}
```