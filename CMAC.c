#include "TDES.h"
#include "CBC_MAC.h"

#include <linux/types.h>
#include <linux/string.h>
#include <linux/unistd.h>
#include <linux/slab.h>

void CBC_MAC_Generation(uint8_t *inputData, size_t inputLength,
						uint8_t *key, size_t keyLength,
						uint8_t *output)
{
	/* NOTE: The output will always be 8 bytes */
	
	uint8_t subkey1[8];
	uint8_t subkey2[8];

	uint8_t IV[8] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
	
	uint8_t *XOR_Input;
	size_t i;
	
	size_t byteToBeFilled;
	uint8_t *padded_XOR_Input;
	
	GenerateSubkey_TDEA(key, keyLength, subkey1, subkey2);

	if((inputLength % 8) == 0 && inputLength != 0)
	{
		/* Use subkey1 */
		XOR_Input = kmalloc(inputLength, GFP_KERNEL);
		memcpy(XOR_Input, inputData, inputLength);

		ByteArray_XOR(&XOR_Input[inputLength - 8], subkey1, 
						8, &XOR_Input[inputLength - 8]);

		for(i = 0; i < (inputLength/8); i++)
		{
			ByteArray_XOR(XOR_Input + 8*i, IV, 8, XOR_Input + 8*i);
			TDES_Encrypt(XOR_Input + 8*i, key, keyLength, IV);
		}
		memcpy(output, IV, 8);
		kfree(XOR_Input);
	}
	else
	{
		/* Padding to 8*n bytes (one '1' bit and '0' bits for the rest) */
		byteToBeFilled = 8 - (inputLength % 8);
		padded_XOR_Input = kmalloc(inputLength + byteToBeFilled, GFP_KERNEL);
		memcpy(padded_XOR_Input, inputData, inputLength);
		memset(padded_XOR_Input + inputLength, 0x80, 1);
		memset(padded_XOR_Input + inputLength + i + 1, 0x0, byteToBeFilled - 1);
		
		/* Use subkey2 */
		ByteArray_XOR(&padded_XOR_Input[inputLength - 8], subkey2, 8, &padded_XOR_Input[inputLength - 8]);
		for(i = 0; i < (inputLength/8); i++)
		{
			ByteArray_XOR(padded_XOR_Input + 8*i, IV, 8, padded_XOR_Input + 8*i);
			TDES_Encrypt(padded_XOR_Input + 8*i, key, keyLength, IV);
		}
		memcpy(output, IV, 8);

		kfree(padded_XOR_Input);
	}

}


int CBC_MAC_Verification(uint8_t *inputData, size_t inputLength,
						uint8_t *key, size_t keyLength,
						uint8_t *rcvd_MAC)
{
	/* Calculate CMAC from inputData and key */
	uint8_t calculated_MAC[8];
	
	int validation_result;
	
	CMAC_Generation(inputData, inputLength, key, keyLength, calculated_MAC);

	/* Compare calculated MAC with recieved_MAC */
	if(ByteArray_CMP(calculated_MAC, rcvd_MAC, 8))
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
