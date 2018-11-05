#include "DUKPT.h"

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/string.h>

#include "DES.h"

uint64_t PINField_format0(char PIN[14+1])
{
	uint64_t PINField = 0x0;
	uint64_t PIN_digit;
	int i;

	/* 2nd nibble: PIN length */
	PINField |= (uint64_t)(strlen(PIN)) << 56;

	/* 3rd to 3+n nibbles: PIN */
	for (i = 0; i < strlen(PIN); i++)
	{
		PIN_digit = (uint64_t)(PIN[i] - '0');
		PINField |= PIN_digit << (4 * (13 - i));
	}

	/* right padding with 0xF */
	for (i = 0; i < 14 - strlen(PIN); i++)
	{
		PINField |= (uint64_t)0xF << 4 * i;
	}

	return PINField;
}

uint64_t PANField_format0(char PAN[12+1])
{
	uint64_t PANField = 0x0;
	uint64_t PAN_digit;
    
	int i;
	for (i = 0; i < strlen(PAN); i++)
	{
		PAN_digit = (uint64_t)(PAN[i] - '0');
		PANField |= PAN_digit << (4 * (11 - i));
	 }
	return PANField;
}


void Separate_TDES_Keys(char Key[48 + 1], uint64_t TDES_Keys[3])
{
	char c_Keys[3][17];

	int i;
	for (i = 0; i < 3; i++)
	{
		int j;

		strncpy(c_Keys[i], Key + 16 * i, 16);
		c_Keys[i][16] = '\0';

		TDES_Keys[i] = 0x0;

		for (j = 0; j < strlen(c_Keys[i]); j++)
		{
			TDES_Keys[i] = TDES_Keys[i] << 0x4;
			if (c_Keys[i][j] >= '0' && c_Keys[i][j] <= '9')
			{
				TDES_Keys[i] += (uint64_t)(c_Keys[i][j] - '0');
			}
			else if (c_Keys[i][j] >= 'a' && c_Keys[i][j] <= 'f')
			{
				TDES_Keys[i] += (uint64_t)(c_Keys[i][j] - 'a' + 10);
			}
			else if (c_Keys[i][j] >= 'A' && c_Keys[i][j] <= 'F')
			{
				TDES_Keys[i] += (uint64_t)(c_Keys[i][j] - 'A' + 10);
			}
    		}
	}
}

void GenerateLRC(FutureKey *FK)
{
	int i;

	FK->LRC = 0;  
	
	for (i = 0; i < 4; i++)
	{
		FK->LRC = FK->LRC + (uint8_t)(FK->LeftHalf >> i * 8);
		//FK->LRC &= (uint8_t)0xFF;
	}
	for (i = 0; i < 4; i++)
	{
		FK->LRC = FK->LRC + (uint8_t)(FK->RightHalf >> i * 8);
		//& (uint8_t)0xFF);
	}
	FK->LRC = (FK->LRC ^ (uint8_t)0xFF) + 1;

}

int checkLRC(FutureKey *FK)
{
	//FK->LRC = 0;
	uint8_t tempLRC = 0;

	int i;
	for (i = 0; i < 4; i++)
	{
		tempLRC = tempLRC + (uint8_t)(FK->LeftHalf >> i * 8);
	}
	for (i = 0; i < 4; i++)
	{
		tempLRC = tempLRC + (uint8_t)(FK->RightHalf >> i * 8);
	}
	tempLRC = (tempLRC ^ (uint8_t)0xFF) + 1;

	if (tempLRC == FK->LRC)
	{
		// check pass
		return 0;
	}
	else
	{
		// check fail
		return 1;
	}
}



void CalcIPEK(uint64_t BDK[2], uint8_t KSN[10], uint64_t IPEK[2])
{
	uint8_t IKSNmask[10] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xE0, 0x00, 0x00};
	uint8_t maskedKSN[10];
	uint64_t IKSN = 0x0;
	uint64_t BDKmask[2] = { 0xC0C0C0C000000000, 0xC0C0C0C000000000 };

	int i;
	for (i = 0; i < 10; i++)
	{
		maskedKSN[i] = IKSNmask[i] & KSN[i];
	}

	for (i = 0; i < 8; i++)
	{
		IKSN |= (uint64_t)(maskedKSN[i]) << (7 - i)*8;
	}
	printk(KERN_INFO "IKSN: %016llX\n", IKSN);

	IPEK[0] = DES_Encrypt(DES_Decrypt(DES_Encrypt(IKSN, BDK[0]), BDK[1]), BDK[0]);
	IPEK[1] = DES_Encrypt(DES_Decrypt(DES_Encrypt(IKSN, BDK[0]^BDKmask[0]), BDK[1]^BDKmask[1]), BDK[0]^BDKmask[0]);

}

/* Generate "child key" with "parent key" + KSN (with counter information) */
void generateKey(uint64_t key[2], uint64_t baseKSN)
{

	uint64_t mask[2] = { 0xC0C0C0C000000000, 0xC0C0C0C000000000 };
	uint64_t maskedKey[2];
	uint64_t left;
	uint64_t right;

	maskedKey[0] = mask[0] ^ key[0];
	maskedKey[1] = mask[1] ^ key[1];

	//printk(KERN_INFO "baseKSN: %016llX | maskedKey: %016llX %016llX\n", baseKSN, maskedKey[0], maskedKey[1]);
	//printk(KERN_INFO "baseKSN: %016llX | key: %016llX %016llX\n", baseKSN, key[0], key[1]);
	left = DES_Encrypt(baseKSN ^ maskedKey[1], maskedKey[0]) ^ maskedKey[1];
	right = DES_Encrypt(baseKSN ^ key[1], key[0]) ^ key[1];
	
	key[0] = left;
	key[1] = right;

}

void NonReversibleKeyGen(DUKPT_Reg* DUKPT_Instance)
{
	uint64_t mask[2] = { 0xC0C0C0C000000000, 0xC0C0C0C000000000 };
	uint64_t maskedKey[2];
	maskedKey[0] = mask[0] ^ DUKPT_Instance->KeyReg[0];
	maskedKey[1] = mask[1] ^ DUKPT_Instance->KeyReg[1];

	//printk(KERN_INFO "baseKSN: %016llx | key: %016llx %016llx\n", DUKPT_Instance->CryptoReg[0], DUKPT_Instance->KeyReg[0], DUKPT_Instance->KeyReg[1]);
	//printk(KERN_INFO "baseKSN: %016llx | maskedKey: %016llx %016llx\n", DUKPT_Instance->CryptoReg[0], maskedKey[0], maskedKey[1]);
	DUKPT_Instance->CryptoReg[1] = DES_Encrypt(DUKPT_Instance->CryptoReg[0] ^ DUKPT_Instance->KeyReg[1], DUKPT_Instance->KeyReg[0]);
	DUKPT_Instance->CryptoReg[1] ^= DUKPT_Instance->KeyReg[1];
	DUKPT_Instance->CryptoReg[0] = DES_Encrypt(DUKPT_Instance->CryptoReg[0] ^ maskedKey[1], maskedKey[0]);
	DUKPT_Instance->CryptoReg[0] ^= maskedKey[1];

}


void NewKey(DUKPT_Reg *DUKPT_Instance)
{
	int oneCount = 0;
	uint32_t EncryptCounter = 0x0;
	int i;

	EncryptCounter |= (uint32_t)(DUKPT_Instance->KSNReg[7] & 0x1F) << 16;
	EncryptCounter |= (uint32_t)(DUKPT_Instance->KSNReg[8]) << 8;
	EncryptCounter |= (uint32_t)(DUKPT_Instance->KSNReg[9]);

	for (i = 0; i < 21; i++)
	{
		if (EncryptCounter & (uint32_t)0x1U << i)
		{
			oneCount++;
		}
	}

	if (oneCount < 10)
	{
		NewKey_1(DUKPT_Instance);
	}
	else
	{
		/* Erase the current key */
		DUKPT_Instance->CurrentKeyPtr->LeftHalf = 0x0;
		DUKPT_Instance->CurrentKeyPtr->RightHalf = 0x0;
		DUKPT_Instance->CurrentKeyPtr->LRC = DUKPT_Instance->CurrentKeyPtr->LRC + 1;

		EncryptCounter += (uint32_t)DUKPT_Instance->ShiftReg;

		DUKPT_Instance->KSNReg[7] = (uint8_t)(EncryptCounter >> 16) & 0x1F;
		DUKPT_Instance->KSNReg[8] = (uint8_t)(EncryptCounter >> 8);
		DUKPT_Instance->KSNReg[9] = (uint8_t)(EncryptCounter);

		NewKey_2(DUKPT_Instance);
	}

}

void NewKey_3(DUKPT_Reg *DUKPT_Instance)
{

	uint64_t KSN_right64 = (uint64_t)0x0;
	uint64_t mask = (uint64_t)0x1 << 20;

	int i;
	for (i = 2; i < 10; i++)
	{
		KSN_right64 <<= 8;
		KSN_right64 |= (uint64_t)DUKPT_Instance->KSNReg[i];
	}

	DUKPT_Instance->CryptoReg[0] = DUKPT_Instance->ShiftReg | KSN_right64;

	
	DUKPT_Instance->KeyReg[0] = DUKPT_Instance->CurrentKeyPtr->LeftHalf;
	DUKPT_Instance->KeyReg[1] = DUKPT_Instance->CurrentKeyPtr->RightHalf;

	NonReversibleKeyGen(DUKPT_Instance);

	for (i = 0; i < 21; i++)
	{
		// NOTE: Shift register from lowest# to highest# from left to right
		if (DUKPT_Instance->ShiftReg & mask)
		{
			DUKPT_Instance->FKReg[i].LeftHalf = DUKPT_Instance->CryptoReg[0];
			DUKPT_Instance->FKReg[i].RightHalf = DUKPT_Instance->CryptoReg[1];
			GenerateLRC(&DUKPT_Instance->FKReg[i]);
			break;
		}
		mask >>= 1;
	}

	//printDUKPTStateSummary(DUKPT_Instance);
	
	NewKey_1(DUKPT_Instance);

}

void NewKey_1(DUKPT_Reg *DUKPT_Instance)
{

	DUKPT_Instance->ShiftReg >>= 1;
	if (DUKPT_Instance->ShiftReg == (uint64_t)0x0)
	{
		/* go to NewKey-4 */
		NewKey_4(DUKPT_Instance);
	}
	else
	{
		/* go to NewKey-3 again */
		NewKey_3(DUKPT_Instance);
	}
}

int NewKey_2(DUKPT_Reg *DUKPT_Instance)
{

	if ((DUKPT_Instance->KSNReg[9] & 0xff) | (DUKPT_Instance->KSNReg[8] & 0xff) | (DUKPT_Instance->KSNReg[7] & 0x1f))
	{
		/* Exit */
		//printk(KERN_INFO "DUKPT initialized successfully\n");
		return 0;
	}
	else
	{
		/* Cease operation. */
		printk(KERN_INFO "The PIN Entry Device is now inoperative, having encrypted more than 1 million PINs\n");
		return 1;
	}

}

void NewKey_4(DUKPT_Reg *DUKPT_Instance)
{
	/* Erase the current key (NOTE: The key has been extracted and store in Key Register) */
	uint32_t tempEncryptCounter = 0x0;
	
	DUKPT_Instance->CurrentKeyPtr->LeftHalf = 0x0;
	DUKPT_Instance->CurrentKeyPtr->RightHalf = 0x0;
	DUKPT_Instance->CurrentKeyPtr->LRC = DUKPT_Instance->CurrentKeyPtr->LRC + 1;

	tempEncryptCounter += DUKPT_Instance->KSNReg[9];
	tempEncryptCounter += DUKPT_Instance->KSNReg[8] << 8;
	tempEncryptCounter += (DUKPT_Instance->KSNReg[7] & (uint8_t)0x1F) << 16;

	tempEncryptCounter += 1; // Increment by 1
	tempEncryptCounter &= (uint32_t)0x1FFFFF; // Discard overflow bit

	DUKPT_Instance->KSNReg[9] = (uint8_t)tempEncryptCounter;
	DUKPT_Instance->KSNReg[8] = (uint8_t)(tempEncryptCounter >> 8);
	DUKPT_Instance->KSNReg[7] &= (uint8_t)0xE0; // clear counter bits
	DUKPT_Instance->KSNReg[7] |= (uint8_t)(tempEncryptCounter >> 16); // assign new counter bits

	NewKey_2(DUKPT_Instance);
}

void Request_PIN_Entry_1(DUKPT_Reg* DUKPT_Instance)
{
	
	int positionShiftReg = 0;
	int i;

	SetBit(DUKPT_Instance);

	for (i = 0; i < 21; i++)
	{
		if (DUKPT_Instance->ShiftReg & (uint64_t)0x100000 >> i)
		{
			break;
		}
		positionShiftReg++;
	}
	DUKPT_Instance->CurrentKeyPtr = &(DUKPT_Instance->FKReg[positionShiftReg]);

	if (checkLRC(DUKPT_Instance->CurrentKeyPtr) == 0)
	{
		/****** LRC check passed  ******/
		/* Request PIN Entry 2 */
		Request_PIN_Entry_2(DUKPT_Instance);
	}
	else
	{
		/****** LRC check failed *******/
		uint32_t EncryptCounter = 0x0;
		EncryptCounter |= (uint32_t)(DUKPT_Instance->KSNReg[7] & 0x1F) << 16;
		EncryptCounter |= (uint32_t)(DUKPT_Instance->KSNReg[8]) << 8;
		EncryptCounter |= (uint32_t)(DUKPT_Instance->KSNReg[9]);

		EncryptCounter = EncryptCounter + DUKPT_Instance->ShiftReg;
		EncryptCounter &= (uint32_t)0x1FFFFF;

		DUKPT_Instance->KSNReg[9] = (uint8_t)EncryptCounter;
		DUKPT_Instance->KSNReg[8] = (uint8_t)(EncryptCounter >> 8);
		DUKPT_Instance->KSNReg[7] &= (uint8_t)0xE0; // clear counter bits
		DUKPT_Instance->KSNReg[7] |= (uint8_t)(EncryptCounter >> 16); // assign new counter bits


		if (EncryptCounter == 0)
		{
			/* Cease Operation: more than 1 million PINs have been encrypted */
			return;
		}
		else 
		{
			Request_PIN_Entry_1(DUKPT_Instance); // Recursive
		}
	}

}

void Request_PIN_Entry_2(DUKPT_Reg* DUKPT_Instance)
{

	uint64_t PIN_variant_const[2] = { 0x00000000000000FF, 0x00000000000000FF };

	DUKPT_Instance->KeyReg[0] = (*(DUKPT_Instance->CurrentKeyPtr)).LeftHalf;
	DUKPT_Instance->KeyReg[1] = (*(DUKPT_Instance->CurrentKeyPtr)).RightHalf;

	DUKPT_Instance->KeyReg[0] ^= PIN_variant_const[0];
	DUKPT_Instance->KeyReg[1] ^= PIN_variant_const[1];

	DUKPT_Instance->CryptoReg[0] = DES_Encrypt(DUKPT_Instance->CryptoReg[0], DUKPT_Instance->KeyReg[0]);
	DUKPT_Instance->CryptoReg[0] = DES_Decrypt(DUKPT_Instance->CryptoReg[0], DUKPT_Instance->KeyReg[1]);
	DUKPT_Instance->CryptoReg[0] = DES_Encrypt(DUKPT_Instance->CryptoReg[0], DUKPT_Instance->KeyReg[0]);

	/* Format and transmit encrypted PIN Block */
	printk(KERN_INFO "=======================================================\n");
	printk(KERN_INFO "                   Transaction Message                 \n");
	printk(KERN_INFO "=======================================================\n");
	printk(KERN_INFO "KSN = %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n", 
						DUKPT_Instance->KSNReg[0], DUKPT_Instance->KSNReg[1], 
						DUKPT_Instance->KSNReg[2], DUKPT_Instance->KSNReg[3], 
						DUKPT_Instance->KSNReg[4], DUKPT_Instance->KSNReg[5], 
						DUKPT_Instance->KSNReg[6], DUKPT_Instance->KSNReg[7], 
						DUKPT_Instance->KSNReg[8], DUKPT_Instance->KSNReg[9]);
	printk(KERN_INFO "Encrypted PIN Block: %016llX\n", DUKPT_Instance->CryptoReg[0]);

	/* New Key */
	//NewKey(DUKPT_Instance);

	//printDUKPTStateSummary(DUKPT_Instance);
}


void SetBit(DUKPT_Reg* DUKPT_Instance)
{

	uint32_t EncryptCounter = 0x0;
	int i;

	DUKPT_Instance->ShiftReg = (uint64_t)0x0;
	EncryptCounter += DUKPT_Instance->KSNReg[9];
	EncryptCounter += DUKPT_Instance->KSNReg[8] << 8;
	EncryptCounter += (DUKPT_Instance->KSNReg[7] & (uint8_t)0x1F) << 16;
	
	for (i = 0; i < 21; i++)
	{
		if (EncryptCounter & ((uint32_t)0x1U << i))
		{
			DUKPT_Instance->ShiftReg |= (uint32_t)0x1U << i;
			break;
		}
	}
}


void printDUKPTStateSummary(DUKPT_Reg *DUKPT_Instance)
{
	int i;

	printk(KERN_INFO "=======================================================\n");
	printk(KERN_INFO "                       State Summary                   \n");
	printk(KERN_INFO "=======================================================\n");
	
	for (i = 0; i < 21; i++)
	{
		printk(KERN_INFO "Future Key #%d: %016llX %016llX | LRC: 0x%02X \n", i + 1, DUKPT_Instance->FKReg[i].LeftHalf, DUKPT_Instance->FKReg[i].RightHalf, DUKPT_Instance->FKReg[i].LRC);
	}
	printk(KERN_INFO "Key Register: %016llX %016llX\n", DUKPT_Instance->KeyReg[0], DUKPT_Instance->KeyReg[1]);
	printk(KERN_INFO "Encryption Counter: 0x%02x%02x%02x\n", DUKPT_Instance->KSNReg[7] & 0x1F, DUKPT_Instance->KSNReg[8], DUKPT_Instance->KSNReg[9]);
	printk(KERN_INFO "Shift Register: 0x%016llX\n", DUKPT_Instance->ShiftReg);
}


