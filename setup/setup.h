#ifndef SETUP_H
#define SETUP_H

#include <stdio.h>
#include <string.h>
#include "mbedtls/pem.h"
#include "mbedtls/error.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_spiffs.h"
#include "esp_system.h"
#include "mbedtls/rsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

// General setup functions
void setup_storage(void);

void setup_entropy_ctr_drbg(mbedtls_entropy_context *entropy, mbedtls_ctr_drbg_context *ctr_drbg, const char *personalization);

void reset_entropy_ctr_drbg(mbedtls_entropy_context *entropy, mbedtls_ctr_drbg_context *ctr_drbg, const char *personalization);

// AES setup functions
unsigned char *aes_pad(unsigned char *input, size_t input_len, size_t *padded_len);

unsigned char *aes_unpad(unsigned char *input, size_t input_len, size_t *output_len);

void setup_aes_key_iv(mbedtls_ctr_drbg_context *ctr_drbg, unsigned char *key, size_t key_len, unsigned char *iv, size_t iv_len);

unsigned char *setup_aes_integrity_msg(unsigned char *key, size_t key_len, unsigned char *iv, size_t iv_len, unsigned char *input, size_t input_len, size_t *integrity_len);

// SHA setup functions

unsigned char *setup_sha_output_buffer(int is224, size_t *output_len);

// Envelope setup functions

unsigned char *setup_envelope(unsigned char *enc_key, size_t enc_key_len, unsigned char *iv, size_t iv_len, unsigned char *ciphertext, size_t ciphertext_len, unsigned char *HMAC, size_t HMAC_len, size_t *envelope_len);

size_t parse_size_from_envelope(unsigned char *envelope, size_t envelope_len, int neg_offset);

const unsigned char *parse_information_from_envelope(unsigned char *envelope, size_t envelope_len, size_t info_len, int neg_offset);

#endif // SETUP_H