#include "Universal.h"

typedef struct KEYPAIR {
    int PublicKey[2]{0};
    int PrivateKey[2]{0};
} KEYPAIR;

class GentlemanProtocol {
   private:
    unsigned int StrLength;
    int PrimeNum[2]{0};
    int RandPrimeNumInterval[2] = {16, 128};

    bool PrimeNumberJudgment(int Num);
    bool RandomPrimeNumber();
    bool KeyPairCalculation();

    int *ASCII_EnCoding(String StrInput);
    String ASCII_DeCoding(int *DecInput);

   public:
    KEYPAIR KeyPair;
    void SetRandRange(int LVALUE, int RVALUE);

    KEYPAIR GenerateKeyPair();
    String Encrypt(String Origin_Str, int Key[2]);
    String Decrypt(String Cipher_Str, int Key[2]);
};