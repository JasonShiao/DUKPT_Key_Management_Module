#include <linux/types.h>
#include <linux/unistd.h>


typedef struct
{
	uint64_t LeftHalf;
	uint64_t RightHalf;
	uint8_t LRC;

}FutureKey;

typedef enum
{
	DUKPT_ACTIVE,
	DUKPT_OVERFLOW
}DUKPT_State;

typedef struct
{
	DUKPT_State current_state;

	uint64_t AccountReg;

	uint8_t KSNReg[10];		// Key Serial Number Register (59-bit + 21-bit)
	FutureKey FKReg[21];	// Future Key Register 
	uint64_t KeyReg[2];		// Key Register
	uint64_t CryptoReg[2];	// Crypto Register
	uint64_t ShiftReg;		// only right-most 21-bit should be used
	FutureKey *CurrentKeyPtr;	// Current Key Pointer (Point to element of Future Key Register)

}DUKPT_Reg;



uint64_t PINField_format0(char PIN[14+1]);
uint64_t PANField_format0(char PAN[12+1]);

void Separate_TDES_Keys(char Key[48 + 1], uint64_t TDES_Key[3]);
void GenerateLRC(FutureKey *FK);
int checkLRC(FutureKey *FK);

void CalcIPEK(uint64_t BDK[2], uint8_t KSN[10], uint64_t IPEK[2]);
void generateKey(uint64_t key[2], uint64_t baseKSN);
void NonReversibleKeyGen(DUKPT_Reg* DUKPT_Instance);

void NewKey_3(DUKPT_Reg* DUKPT_Instance);
int NewKey_1(DUKPT_Reg* DUKPT_Instance);
void NewKey_4(DUKPT_Reg* DUKPT_Instance);
int NewKey_2(DUKPT_Reg* DUKPT_Instance);

int NewKey(DUKPT_Reg* DUKPT_Instance);

int Request_PIN_Entry_1(DUKPT_Reg* DUKPT_Instance);
void Request_PIN_Entry_2(DUKPT_Reg* DUKPT_Instance);

void SetBit(DUKPT_Reg* DUKPT_Instance);

void printDUKPTStateSummary(DUKPT_Reg* DUKPT_Instance);

