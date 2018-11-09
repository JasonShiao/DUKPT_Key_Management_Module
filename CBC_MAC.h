#ifndef CMAC_H
#define CMAC_H

#include <linux/types.h>

void CBC_MAC_Generation(uint8_t *inputData, 
						size_t inputLength,
						char *blockcipher,
						uint8_t *key, 
						size_t keyLength,
						uint8_t *result);

int CBC_MAC_Verification(uint8_t *inputData, 
						size_t inputLength,
						char *blockcipher,
						uint8_t *key, 
						size_t keyLength,
						uint8_t *rcvd_MAC);

void ByteArray_XOR(const uint8_t * const input1,
					const uint8_t * const input2,
					size_t length,
					uint8_t *output);

int ByteArray_CMP(const uint8_t * const input1,
					const uint8_t * const input2,
					size_t length);


#endif
