#ifndef TDES_H
#define TDES_H

#include <linux/unistd.h>
#include <linux/types.h>

uint64_t TDES_Encrypt_Block(uint64_t text,
							uint64_t key1,
							uint64_t key2,
							uint64_t key3);

uint64_t TDES_Decrypt_Block(uint64_t ciphertext,
							uint64_t key1,
							uint64_t key2,
							uint64_t key3);

void TDES_Encrypt(uint8_t *text,
					size_t textLength,
					uint8_t *key,
					size_t keylength, 
					uint8_t *result);

void TDES_Decrypt(uint8_t *ciphertext,
					size_t textLength,
					uint8_t *key, 
					size_t keylength, 
					uint8_t *result);

int TDEA_CBC_Encrypt(uint8_t *inputData, 
						size_t length, 
						uint8_t *key, 
						size_t keylength, 
						uint8_t *IV, 
						uint8_t *result);

int TDEA_CBC_Decrypt(uint8_t *inputData,
						size_t length,
						uint8_t *key,
						size_t keylength,
						uint8_t *IV,
						uint8_t *result);

void uint64_to_ByteArray(uint64_t input, uint8_t *output);
void ByteArray_to_uint64(uint8_t *input, uint64_t *output);

#endif
