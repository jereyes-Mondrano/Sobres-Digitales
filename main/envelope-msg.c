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
#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"
#include "setup.h"

unsigned char *create_envelope(unsigned char *plaintext, size_t plaintext_len, size_t *envelope_len) {

    printf("\nCreating Envelope...\n\n");

    /*
     * Setup the entropy and CTR-DRBG.
     */

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *personalization = "envelope_msg";
    setup_entropy_ctr_drbg(&entropy, &ctr_drbg, personalization);


    /*
     * Setup the AES context, the key and IV.
     * Note: The AES key and IV should be set up properly before use.
     */

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    unsigned char aeskey[32]; // 256-bit key for AES
    unsigned char iv[16]; // 128-bit IV for AES
    size_t aeskey_len = sizeof(aeskey);
    size_t iv_len = sizeof(iv);

    /*
     * Initialize the AES encryption key and IV
     */

    setup_aes_key_iv(&ctr_drbg, aeskey, aeskey_len, iv, iv_len);
    mbedtls_aes_setkey_enc( &aes, aeskey, aeskey_len * 8 ); // bytes to bits conversion

    /*
     * Store IV for encryption scope
     * NOTE: For some reason the encryption function below modifies the IV and messes up the process
     */
     
    unsigned char *enc_iv = malloc(iv_len);
    memcpy(enc_iv, iv, iv_len);

    /*
     * Prepare the AES input data and output buffer.
     * Note: The input data should be padded to a multiple of 16 bytes for AES
     */

    size_t padded_plaintext_len = 0;
    unsigned char *padded_plaintext = aes_pad(plaintext, plaintext_len, &padded_plaintext_len);

    unsigned char ciphertext[padded_plaintext_len]; // Output buffer for AES encryption
    size_t ciphertext_len = sizeof(ciphertext); // This should match padded_plaintext_len

    /* 
     * Encrypt the padded AES input
     */

    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_plaintext_len, enc_iv, padded_plaintext, ciphertext);
    printf("Plaintext encrypted succesfully.\n");

    /*
     * Setup PK context for key encapsulation
     */

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    /*
     * Read the RSA public key
     */
    int ret;
    if( ( ret = mbedtls_pk_parse_public_keyfile( &pk, "/storage/publickey.crt" ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_pk_parse_public_keyfile returned -0x%04x\n", -ret );
    } else {
        printf("Public key loaded successfully.\n");
    }

    /*
     * Calculate the RSA encryption of the data.
     */

    unsigned char encrypted_aeskey[MBEDTLS_MPI_MAX_SIZE];
    size_t encrypted_aeskey_len = 0;

    if( ( ret = mbedtls_pk_encrypt( &pk, aeskey, aeskey_len,
                                    encrypted_aeskey, &encrypted_aeskey_len, sizeof(encrypted_aeskey),
                                    mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_pk_encrypt returned -0x%04x\n", -ret );
    } else {
        printf("AES key encrypted successfully.\n");
    }

    /*
     * Setup SHA256 context and output buffer for hashing
     */

    mbedtls_sha256_context sha256;
    mbedtls_sha256_init(&sha256);

    int is224 = 0; // 0 for SHA-256, 1 for SHA-224
    size_t hmac_len;

    unsigned char *hmac = setup_sha_output_buffer(is224, &hmac_len);

    /*
     * Prepare message for integrity check
     * Note: The format is (AES key | IV | AES output | AES output length)
     */

    size_t integrity_len;
    unsigned char *integrity_msg = setup_aes_integrity_msg(encrypted_aeskey, encrypted_aeskey_len, iv, iv_len, ciphertext, ciphertext_len, &integrity_len);

    /*
     * Perform SHA256 hashing on the integrity message
     */

    ret = mbedtls_sha256(integrity_msg, integrity_len, hmac, is224);
    if (ret != 0) {
        printf( " failed\n ! mbedtls_sha256 returned -0x%04x\n", -ret );
    } else {
        printf("SHA256 hash computed successfully.\n");
    }

    /*
     * Prepare Envelope
     */

    unsigned char *envelope = setup_envelope(encrypted_aeskey, encrypted_aeskey_len, iv, iv_len, ciphertext, ciphertext_len, hmac, hmac_len, envelope_len);
    
    return envelope;
}

unsigned char *open_envelope(unsigned char *envelope, size_t envelope_len, size_t *output_len) {
    // This function should parse the envelope and return the decrypted data.

    printf("\nOpening envelope...\n\n");

    /*
     * Parse the SHA output length and data.
     */
    size_t HMAC_output_len = parse_size_from_envelope(envelope, envelope_len, sizeof(size_t));

    int HMAC_output_offset = HMAC_output_len + sizeof(size_t);
    const unsigned char *HMAC_output = parse_information_from_envelope(envelope, envelope_len, HMAC_output_len, HMAC_output_offset);

    /*
     * Parse the ciphertext length and data
     */

    size_t ciphertext_len = parse_size_from_envelope(envelope, envelope_len, HMAC_output_offset + sizeof(size_t));

    int ciphertext_offset = HMAC_output_offset + sizeof(size_t) + ciphertext_len;
    const unsigned char *ciphertext = parse_information_from_envelope(envelope, envelope_len, ciphertext_len, ciphertext_offset);

    /*
     * Parse the IV length and data
     */

    size_t dec_iv_len = parse_size_from_envelope(envelope, envelope_len, ciphertext_offset + sizeof(size_t));

    int dec_iv_offset = ciphertext_offset + sizeof(size_t) + dec_iv_len;
    const unsigned char *dec_iv = parse_information_from_envelope(envelope, envelope_len, dec_iv_len, dec_iv_offset);

    /*
     * Parse the AES key length and data
     */

    size_t enc_aeskey_len = parse_size_from_envelope(envelope, envelope_len, dec_iv_offset + sizeof(size_t));

    int enc_aeskey_offset = dec_iv_offset + sizeof(size_t) + enc_aeskey_len;
    const unsigned char *enc_aeskey = parse_information_from_envelope(envelope, envelope_len, enc_aeskey_len, enc_aeskey_offset);

    /*
     * Verify the SHA256 hash of the integrity message
     */

    mbedtls_sha256_context sha256;
    mbedtls_sha256_init(&sha256);

    int is224 = 0; // 0 for SHA-256, 1 for SHA-224
    size_t sha_output_len;

    unsigned char *sha_output = setup_sha_output_buffer(is224, &sha_output_len);

    /*
     * Prepare message for integrity check
     * Note: The format is (AES key | IV | AES output | AES output length)
     */

    size_t integrity_len;
    unsigned char *integrity_msg = setup_aes_integrity_msg(enc_aeskey, enc_aeskey_len, dec_iv, dec_iv_len, ciphertext, ciphertext_len, &integrity_len);

    /*
     * Perform SHA256 hashing on the integrity message
     */

    int ret;
    ret = mbedtls_sha256(integrity_msg, integrity_len, sha_output, is224);
    if (ret != 0) {
        printf( " failed\n ! mbedtls_sha256 returned -0x%04x\n", -ret );
    } else {
        printf("SHA256 hash computed successfully.\n");
    }

    /*
     * Verify the SHA256 hash against the one in the envelope
     */

    if (memcmp(sha_output, HMAC_output, HMAC_output_len) != 0) {
        printf("Integrity verification failed.\n");
        return NULL; // Hash verification failed
    } else {
        printf("Integrity verification succeeded.\n");
    }

    /*
     * Prepares the PK context, entropy and ctr_drbg, for the decryption of the AES key
     */

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    char *personalization = "my_nonce";

    setup_entropy_ctr_drbg(&entropy, &ctr_drbg, personalization);

    /*
     * Load the private key from the file system.
     */

    if( ( ret = mbedtls_pk_parse_keyfile( &pk, "/storage/keypair.pem", NULL, mbedtls_ctr_drbg_random, &ctr_drbg) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_pk_parse_keyfile returned -0x%04x\n", -ret );
    } else {
        printf("Private key loaded successfully.\n");
    }

    /*
     * Decrypt the AES key using the private key.
     */

    unsigned char aeskey[MBEDTLS_MPI_MAX_SIZE];

    size_t aeskey_len;

    if( ( ret = mbedtls_pk_decrypt( &pk, enc_aeskey, enc_aeskey_len, aeskey, &aeskey_len, sizeof(aeskey),
                                    mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_pk_decrypt returned -0x%04x\n", -ret );
    } else {
        printf("AES key decrypted successfully.\n");
    }

    /*
     * Setup the AES context and key for decryption.
     */

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    mbedtls_aes_setkey_dec(&aes, aeskey, aeskey_len * 8); // bytes to bits conversion

    /*
     * Prepare the output buffer for the decrypted data.
     */

    size_t padded_plaintext_len = ciphertext_len; // Assuming the output will be the same length as ciphertext
    unsigned char padded_plaintext[padded_plaintext_len];

    /*
     * Decrypt the ciphertext using AES in CBC mode.
     */

    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, ciphertext_len, dec_iv, ciphertext, padded_plaintext);
    printf("Ciphertext decryption completed successfully.\n");

    /*
     * Unpad the decrypted data.
     */

    size_t plaintext_len;
    unsigned char *plaintext = aes_unpad(padded_plaintext, padded_plaintext_len, &plaintext_len);
    
    return plaintext;
}

void app_main() {

    /*
     * Setup the filesystem
     */

    setup_storage();

    /*
     * Create a sample plaintext message to be encrypted.
     */

    unsigned char plaintext[] = "This is a secret message.";
    size_t plaintext_len = sizeof(plaintext) - 1; // Exclude null terminator

    /*
     * Create Envelope
     */

    size_t envelope_len;
    unsigned char *envelope = create_envelope(plaintext, plaintext_len, &envelope_len);

    /*
     * Open Envelope
     */

    size_t output_len;
    unsigned char *decrypted_output = open_envelope(envelope, envelope_len, &output_len);
    
    printf( "\nDecrypted output: %s\n", decrypted_output);
}