#ifndef HMAC_H
#define HMAC_H

#include <stdio.h>
#include "sha256/sha256.h"
#include <stdint.h>
#include <stddef.h>

int hmac_sha256(const uint8_t *key, size_t key_len,
                  const uint8_t *message, size_t message_len,
                  uint8_t *output);

#endif