#include "setup.h"
#include <stdio.h>

// General setup functions

void setup_storage(void) {
    esp_vfs_spiffs_conf_t conf = {
        .base_path = "/storage",
        .partition_label = NULL,
        .max_files = 5,
        .format_if_mount_failed = true
    };

    esp_err_t result_n = esp_vfs_spiffs_register(&conf);
    if (result_n != ESP_OK) {
        printf("SPIFFS mount failed\n");
    }

    // Now you can access "/storage"
    printf("SPIFFS mounted successfully\n");
}

void setup_entropy_ctr_drbg(mbedtls_entropy_context *entropy, mbedtls_ctr_drbg_context *ctr_drbg, const char *personalization) {
    mbedtls_entropy_init(entropy);
    mbedtls_ctr_drbg_init(ctr_drbg);

    int ret = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy, (const unsigned char *)personalization, strlen(personalization));
    if (ret != 0) {
        printf("mbedtls_ctr_drbg_seed failed: -0x%04x\n", -ret);
    }
}

void reset_entropy_ctr_drbg(mbedtls_entropy_context *entropy, mbedtls_ctr_drbg_context *ctr_drbg, const char *personalization) {
    mbedtls_entropy_free(entropy);
    mbedtls_ctr_drbg_free(ctr_drbg);
    setup_entropy_ctr_drbg(entropy, ctr_drbg, personalization);
}

// AES setup functions

void setup_aes_key_iv(mbedtls_ctr_drbg_context *ctr_drbg, unsigned char *key, size_t key_len, unsigned char *iv, size_t iv_len) {
    int ret;
    if( ( ret = mbedtls_ctr_drbg_random( ctr_drbg, key, key_len ) ) != 0 ) {
        printf( " failed\n ! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret );
    } else {
        printf("AES key generated successfully\n");
    }

    if( ( ret = mbedtls_ctr_drbg_random( ctr_drbg, iv, iv_len ) ) != 0 ) {
        printf( " failed\n ! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret );
    } else {
        printf("AES IV generated successfully\n");
    }
}

unsigned char *setup_aes_integrity_msg(unsigned char *key, size_t key_len, unsigned char *iv, size_t iv_len, unsigned char *input, size_t input_len, size_t *integrity_len) {
    // Prepare an integrity message that includes the key, IV, input data, and the length of the input data
    //Note: The format is (AES key | IV | AES output | AES output length)

    *integrity_len = key_len + iv_len + input_len + sizeof(input_len);
    unsigned char *integrity_msg = malloc(*integrity_len);
    if (integrity_msg == NULL) {
        printf("setup_aes_integrity_msg: Memory allocation failed");
        return NULL;
    }
    
    // Copy the key, IV, input data, and input length into the integrity message
    memcpy(integrity_msg, key, key_len);
    memcpy(integrity_msg + key_len, iv, iv_len);
    memcpy(integrity_msg + key_len + iv_len, input, input_len);
    memcpy(integrity_msg + key_len + iv_len + input_len, &input_len, sizeof(input_len));
    return integrity_msg;
}

unsigned char *aes_pad(unsigned char *input, size_t input_len, size_t *padded_len) {
    // Pad the input to be a multiple of 16 bytes for AES
    size_t padding_len = 16 - (input_len % 16);
    *padded_len = input_len + padding_len;
    unsigned char *padded_input = malloc(*padded_len);
    if (padded_input == NULL) {
        printf("aes_pad: Memory allocation failed");
        return NULL;
    }
    memcpy(padded_input, input, input_len);
    // Specify padding bytes, the padding bytes are the number of padding bytes added
    memset(padded_input + input_len, padding_len, padding_len); 
    return padded_input;
}

unsigned char *aes_unpad(unsigned char *input, size_t input_len, size_t *output_len) {
    // Unpad the input by removing the padding bytes
    // Padding bytes are the same as the last byte value
    size_t padding_len = input[input_len - 1];
    if (padding_len > 16 || padding_len == 0) {
        printf("aes_unpad: Invalid padding length");
        return NULL;
    }
    *output_len = input_len - padding_len;
    unsigned char *unpadded_input = malloc(*output_len);
    if (unpadded_input == NULL) {
        printf("aes_unpad: Memory allocation failed");
        return NULL;
    }
    memcpy(unpadded_input, input, *output_len);
    return unpadded_input;
}

// SHA setup functions

unsigned char *setup_sha_output_buffer(int is224, size_t *output_len) {
    if (is224) {
        *output_len = 224 / 8;
    } else {
        *output_len = 256 / 8;
    }
    unsigned char *output_buf = malloc(*output_len);
    if (output_buf == NULL) {
        printf("setup_sha_output_buffer: Memory allocation failed");
        return NULL;
    }
    return output_buf;
}

// Envelope setup functions

unsigned char *setup_envelope(unsigned char *enc_key, size_t enc_key_len, unsigned char *iv, size_t iv_len, unsigned char *ciphertext, size_t ciphertext_len, unsigned char *HMAC, size_t HMAC_len, size_t *envelope_len) {
    // Prepare an envelope that includes the encryption key, IV, ciphertext, and HMAC
    // Note: The format is (encrypted key | encrypted key length | IV | IV length | ciphertext | ciphertext length | HMAC | HMAC length)

    *envelope_len = enc_key_len + sizeof(enc_key_len) + iv_len + sizeof(iv_len) + ciphertext_len + sizeof(ciphertext_len) + HMAC_len + sizeof(HMAC_len);
    unsigned char *envelope = malloc(*envelope_len);
    if (envelope == NULL) {
        printf("setup_envelope: Memory allocation failed");
        return NULL;
    }
    
    // Copy the encryption key, IV, ciphertext, and HMAC into the envelope
    memcpy(envelope, enc_key, enc_key_len);
    memcpy(envelope + enc_key_len, &enc_key_len, sizeof(enc_key_len));
    memcpy(envelope + enc_key_len + sizeof(enc_key_len), iv, iv_len);
    memcpy(envelope + enc_key_len + sizeof(enc_key_len) + iv_len, &iv_len, sizeof(iv_len));
    memcpy(envelope + enc_key_len + sizeof(enc_key_len) + iv_len + sizeof(iv_len), ciphertext, ciphertext_len);
    memcpy(envelope + enc_key_len + sizeof(enc_key_len) + iv_len + sizeof(iv_len) + ciphertext_len, &ciphertext_len, sizeof(ciphertext_len));
    memcpy(envelope + enc_key_len + sizeof(enc_key_len) + iv_len + sizeof(iv_len) + ciphertext_len + sizeof(ciphertext_len), HMAC, HMAC_len);
    memcpy(envelope + enc_key_len + sizeof(enc_key_len) + iv_len + sizeof(iv_len) + ciphertext_len + sizeof(ciphertext_len) + HMAC_len, &HMAC_len, sizeof(HMAC_len));

    return envelope;
}

size_t parse_size_from_envelope(unsigned char *envelope, size_t envelope_len, int neg_offset) {
    // Parse the size of a specific component from the envelope
    // neg_offset is used to specify the offset from the end of the envelope
    size_t offset = envelope_len - neg_offset;
    if (offset + sizeof(size_t) > envelope_len) {
        return 0;
    }
    size_t size;
    memcpy(&size, envelope + offset, sizeof(size_t));
    return size;
}

const unsigned char *parse_information_from_envelope(unsigned char *envelope, size_t envelope_len, size_t info_len, int neg_offset){
    if (info_len == 0) {
        return NULL;
    }
    size_t offset = envelope_len - neg_offset;
    if (offset + info_len > envelope_len) {
        return NULL;
    }
    unsigned char *info = malloc(info_len);
    if (info == NULL) {
        return NULL;
    }
    memcpy(info, envelope + offset, info_len);
    return info;
}