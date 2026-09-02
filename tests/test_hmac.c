// This will use the RFC 4231 test cases 1 , 3 and 6.
#include "sha256/sha256.h"
#include  <stdlib.h>
#include  <stdio.h>
#include <string.h>
#include "hmac.h"

int main(){
    printf("Test Case 1: \n Data: 'Hi There'\n Key:'0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'\n Expected:'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7' \n");
    uint8_t output[32];
    uint8_t key_one[20];
    memset(key_one, 0x0b, 20);
    const uint8_t *data_one = (const uint8_t *) "Hi There";
    size_t data_one_len = strlen("Hi There");
    hmac_sha256(key_one,20,data_one,data_one_len,output);
    printf("Output: \n");
    for (int i = 0; i < 32; i++) {
        printf("%02x", output[i]);
    }
    printf("\n");
    return 0;
}