#include "TDES.h"

#include <linux/kernel.h>
#include <linux/unistd.h>
#include <linux/types.h>
#include <linux/string.h>

#include "DES.h"


/**
 *	Perform TDES encryption on a single 64-bit text block
 *	@return the encrypted text block
 */
uint64_t TDES_Encrypt_Block(uint64_t text, 
							uint64_t key1, 
							uint64_t key2, 
							uint64_t key3)
{
	return DES_Encrypt_Block(DES_Decrypt_Block(DES_Encrypt_Block(text, key1), key2), key3);
}

/**
 *	Perform TDES decryption on a single 64-bit ciphertext block
 *	@return the encrypted text block
 */
uint64_t TDES_Decrypt_Block(uint64_t ciphertext,
							uint64_t key1,
							uint64_t key2,
							uint64_t key3)
{
	return DES_Decrypt_Block(DES_Encrypt_Block(DES_Decrypt_Block(ciphertext, key1), key2), key3);
}

/** 
 *	@param text must already be padded to a multiple of 8 bytes
 *	@return 0 if invalid input. Otherwise, the encrypted result
 */
void TDES_Encrypt(uint8_t *text,
					size_t textLength,
					uint8_t *key, 
					size_t keyLength,
					uint8_t *result)
{

	if(result == NULL)
	{
		/* result can't be NULL pointer */
		return;
	}

	if(textLength % 8 != 0)
	{
		/* Invalid text length */
		return;
	}

	if(keyLength != 16 && keyLength != 24)
	{
		/* Invalid key length */
		return;
	}
	
	
	DES_Encrypt(text, textLength, key, 8, result);
	DES_Decrypt(result, textLength, key + 8, 8, result);
	if(keyLength == 16)
	{
		DES_Encrypt(result, textLength, key, 8, result);
	}
	else if(keyLength == 24)
	{
		DES_Encrypt(result, textLength, key + 16, 8, result);
	}
}

/** 
 *	@param text must already be padded to a multiple of 8 bytes
 *	@return 0 if invalid input. Otherwise, the encrypted result
 */
void TDES_Decrypt(uint8_t *ciphertext,
					size_t textLength,
					uint8_t *key,
					size_t keyLength,
					uint8_t *result)
{

	if(result == NULL)
	{
		/* result can't be NULL pointer */
		return;
	}

	if(textLength % 8 != 0)
	{
		/* Invalid text length */
		return;
	}

	if(keyLength != 16 && keyLength != 24)
	{
		/* Invalid key length */
		return;
	}
	

	if(keyLength == 16)
	{
		DES_Decrypt(ciphertext, textLength, key, 8, result);
	}
	else if(keyLength == 24)
	{
		DES_Decrypt(ciphertext, textLength, key + 16, 8, result);
	}
	DES_Encrypt(result, textLength, key + 8, 8, result);
	DES_Decrypt(result, textLength, key, 8, result);

}


/** 
 *	Perform TDEA CBC Encryption.
 *	@param inputData must have been padded to a multiple of 8 bytes
 *  @param keyLength must be 16 (two-key) or 24 (three-key)
 *	@param IV must be 8 bytes (if is NULL, it will be assigned with 0 internally)
 *	@return 0 for success, 1 for failed
 */
int TDEA_CBC_Encrypt(uint8_t *inputData, 
						size_t dataLength, 
						uint8_t *key, 
						size_t keyLength, 
						uint8_t *IV, 
						uint8_t *result)
{
	/*
		IV must be 8 bytes (64 bites)
	*/
	size_t i;
	size_t j;

	uint8_t tmpInput[8];
	uint8_t tmpIV[8];
	uint8_t tmpOutput[8];

	uint8_t default_IV[8] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
	
	if(dataLength % 8)
	{
		printk(KERN_ERR "Invalid input data length: Must be a multiple of 8 bytes\n");
		return 1;
	}

	if(IV == NULL)
	{
		IV = default_IV;
	}

	memcpy(tmpIV, IV, 8);

	for(i = 0; i < dataLength/8; i++)
	{
		memcpy(tmpInput, inputData + i*8, 8);
		for(j = 0; j < 8; j++)
		{
			tmpInput[j] ^= tmpIV[j];
		}
		
		TDES_Encrypt(tmpInput, 8, key, keyLength, tmpOutput);
		memcpy(result + i*8, tmpOutput, 8);
		memcpy(tmpIV, tmpOutput, 8);
	}
	return 0;
}

/** Perform TDEA CBC Decryption
 *  
 *	@return 0 for success, 1 for failed
 */
int TDEA_CBC_Decrypt(uint8_t *inputData, 
						size_t dataLength,
						uint8_t *key, 
						size_t keyLength,
						uint8_t *IV, 
						uint8_t *result)
{
	
	/*
		inputData length must be a multiple of 8 bytes
		key length must be 16 (two-key) or 24 (three-key) bytes
		IV must be 8 bytes (64 bites)
	*/
	size_t i;
	size_t j;

	uint8_t tmpInput[8];
	uint8_t tmpIV[8];
	uint8_t tmpOutput[8];
	
	uint8_t default_IV[8] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
	
	if(dataLength % 8)
	{
		printk(KERN_ERR "Invalid input data length: Must be a multiple of 8 bytes\n");
		return 1;
	}

	if(IV == NULL)
	{
		IV = default_IV;
	}

	memcpy(tmpIV, IV, 8);
	
	for(i = 0; i < dataLength/8; i++)
	{
		memcpy(tmpInput, inputData + i*8, 8);
		TDES_Decrypt(tmpInput, 8, key, keyLength, tmpOutput);
		
		for(j = 0; j < 8; j++)
		{
			tmpOutput[j] ^= tmpIV[j];
		}
		
		memcpy(result + i*8, tmpOutput, 8);
		memcpy(tmpIV, tmpInput, 8);
	}
	return 0;
}

