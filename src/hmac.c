#include "src/sha256/sha256.h"
#include  <stdlib.h>
#include  <stdio.h>
#include <string.h>
#include "hmac.h"

#define BLOCK_SIZE 64
#define HASH_SIZE 32
#define IPAD_BYTE 0x36
#define OPAD_BYTE 0x5c

void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *message, size_t message_len, uint8_t *output)
{
    uint8_t k_prime[64];

    if(key_len > BLOCK_SIZE){ // if the key is too long it gets hashed and then padded
        sha256(key, key_len, k_prime);
        memset(k_prime + 32, 0, 32);
    }else{
        memcpy(k_prime, key, key_len); //if the key is too short it gets copied and padded
        memset(k_prime + key_len, 0, 64-key_len);
    }


}