#ifndef DES_H
#define DES_H


#include <linux/unistd.h>
#include <linux/types.h>



uint64_t DES_Encrypt_Block(uint64_t text, uint64_t key);
uint64_t DES_Decrypt_Block(uint64_t ciphertext, uint64_t key);

void DES_Encrypt(uint8_t *text,
				size_t textLength,
				uint8_t *key,
				size_t keyLength,
				uint8_t *result);
void DES_Decrypt(uint8_t *cipherText,
				size_t textLength,
				uint8_t *key,
				size_t keyLength,
				uint8_t *result);

uint64_t InitPermutation(uint64_t input);
uint64_t FinalPermutation(uint64_t input);

uint32_t Feistel(uint32_t half_block, uint64_t subkey);
uint64_t Expansion(uint32_t half_block);
uint32_t Permutation(uint32_t half_block);
uint32_t Substitution(uint64_t input, const unsigned int SBox[4][16]);

void GenSubkey(uint64_t key, uint64_t subkey[16]);


void uint64_to_ByteArray(uint64_t input, uint8_t *output);
void ByteArray_to_uint64(uint8_t *input, uint64_t *output);

#endif
