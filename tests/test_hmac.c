// This will use the RFC 4231 test cases 1, 2 , 3 and 6.
#include "sha256/sha256.h"
#include  <stdlib.h>
#include  <stdio.h>
#include <string.h>
#include "hmac.h"

int main(){
    //test case 1
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
    //test case 2
    printf("Test Case 2: \n Data: 'what do ya want for nothing?'\n Key:'Jefe'\n Expected:'5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843' \n");
    uint8_t output_two[32];
    uint8_t* key_two = (uint8_t*) "Jefe";
    const uint8_t *data_two = (const uint8_t *) "what do ya want for nothing?";
    size_t data_two_len = strlen("what do ya want for nothing?");
    hmac_sha256(key_two,4,data_two,data_two_len,output_two);
    printf("Output: \n");
    for (int i = 0; i < 32; i++) {
        printf("%02x", output_two[i]);
    }
    printf("\n");
    
    //test case 3
    printf("Test Case 3: \n Data: '0xdd(50 times)'\n Key:'0xaa(20 times)'\n Expected:'773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe' \n");
    uint8_t output_three[32];
    uint8_t key_three[20];
    memset(key_three, 0xaa, 20);
    uint8_t data_three[50];
    memset(data_three, 0xdd, 50);
    size_t data_three_len = 50;
    hmac_sha256(key_three,20,data_three,data_three_len,output_three);
    printf("Output: \n");
    for (int i = 0; i < 32; i++) {
        printf("%02x", output_three[i]);
    }
    printf("\n");
    
    //test case 6
    
    printf("Test Case 6: \n Data: 'Test Using Larger Than Block-Size Key - Hash Key First'\n Key:'0xaa(131 times)'\n Expected:'60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54' \n");
    uint8_t output_six[32];
    uint8_t key_six[131];
    memset(key_six, 0xaa, 131);
    const uint8_t *data_six = (const uint8_t *) "Test Using Larger Than Block-Size Key - Hash Key First";
    size_t data_six_len = strlen("Test Using Larger Than Block-Size Key - Hash Key First");
    hmac_sha256(key_six,131,data_six,data_six_len,output_six);
    printf("Output: \n");
    for (int i = 0; i < 32; i++) {
        printf("%02x", output_six[i]);
    }
    printf("\n");
    
    
    return 0;
}