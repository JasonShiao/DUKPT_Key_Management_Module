/*************************************************************
 *					CBC-MAC implementation
 *									
 *								by Jason Shiao, Nov., 2018
 *************************************************************/

#include "DES.h"
#include "TDES.h"
#include "CBC_MAC.h"

#include <linux/types.h>
#include <linux/string.h>
#include <linux/unistd.h>
#include <linux/slab.h>

/**
 *	Generate CBC-MAC with specified blockcipher
 *	@param inputData must always be a multiple of 8 bytes (already padded)
 *	@param blockcipher specifies which blockcipher to use
 *	@param key The key for blockcipher
 *	@param result will always be 8 bytes long
 */
void CBC_MAC_Generation(uint8_t *inputData, 
						size_t inputLength,
						char *blockcipher,
						uint8_t *key, 
						size_t keyLength,
						uint8_t *result)
{
	/* NOTE: The output will always be 8 bytes */

	uint8_t XORed_Input[8];
	uint8_t IV[8] = {0x0, 0x0, 0x0, 0x0, 
					0x0, 0x0, 0x0, 0x0};
	
	size_t i;
	
	/* TODO add more kinds of blockciphers here */
	void (*blockcipher_func_ptr)(uint8_t*, size_t, uint8_t*, size_t, uint8_t*);

	if(strcmp(blockcipher, "TDES") == 0)
	{
		blockcipher_func_ptr = &TDES_Encrypt;
	}
	else if(strcmp(blockcipher, "DES") == 0)
	{
		blockcipher_func_ptr = &DES_Encrypt;
	}
	else
	{
		return;
	}



	if(inputLength % 8 != 0)
	{
		printk(KERN_ERR "Invalid input length for CBC-MAC\n");
		return;
	}
	if(result == NULL)
	{
		printk(KERN_ERR "Output pointer can't be NULL.\n");
		return;
	}

	for(i = 0; i < (inputLength/8); i++)
	{
		ByteArray_XOR(inputData + 8*i, IV, 8, XORed_Input);
		(*blockcipher_func_ptr)(XORed_Input, 8, key, keyLength, IV);
	}
	memcpy(result, IV, 8);

}


int CBC_MAC_Verification(uint8_t *inputData, 
						size_t inputLength,
						char *blockcipher,
						uint8_t *key, 
						size_t keyLength,
						uint8_t *rcvd_MAC)
{
	/* Calculate CMAC from inputData and key */
	uint8_t calculated_MAC[8];
	
	int validation_result;
	
	CBC_MAC_Generation(inputData, 
					inputLength, 
					blockcipher,
					key, 
					keyLength, 
					calculated_MAC);

	/* Compare calculated MAC with recieved_MAC */
	if(ByteArray_CMP(calculated_MAC, rcvd_MAC, 8) != 0)
	{
		/* Failed */
		validation_result = 1;
	}
	else
	{
		/* Success */
		validation_result = 0;
	}

	return validation_result;
}

void ByteArray_XOR(const uint8_t * const input1, 
					const uint8_t * const input2,
					size_t length, 
					uint8_t *output)
{
	size_t i;
	for(i = 0; i < length; i++)
	{
		output[i] = input1[i] ^ input2[i];
	}
}

int ByteArray_CMP(const uint8_t * const input1, 
					const uint8_t * const input2,
					size_t length)
{
	size_t i;
	for(i = 0; i < length; i++)
	{
		if( *(input1 + i) != *(input2 + i))
		{
			return 1; /* 1 for different */
		}
	}
	return 0; /* 0 for identical */
}

