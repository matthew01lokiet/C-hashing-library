# C-hashing-library
![Default Pipeline](https://github.com/matthew01lokiet/C-hashing-library/actions/workflows/pipeline.yml/badge.svg)

C hashing library providing 6 hashing functions and one bonus:
- `SHA-256`
- `SHA-224`
- `SHA-1`
- `SHA-0`
- `MD-5`
- `MD-4`
- `ROT-13`

## Usage Example
```c
#include <stdio.h>
#include <stdlib.h>
#include "hashing.h"

int main() {

    // SHA-224
    uint8_t test_value[] = {'t', 'e', 's', 't'};
    uint32_t* hash = Hashing.sha_224(test_value,4);

    // If some problem, NULL value will get returned
    if(hash == NULL){
        return 1;
    }

    for(int i = 0; i < 7; i++){
        printf("%#010x ", hash[i]);
    }
    printf("\n");
    // Remember about freeing memory allocated for the hash!
    free(hash);

    return 0;
}
```
