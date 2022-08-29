#include "GentlemanProtocol.h"

bool GentlemanProtocol::PrimeNumberJudgment(int Num) {
    bool isPrime = true;
    for (int i = 2; i <= Num / 2; ++i) {
        if (Num % i == 0) {
            isPrime = false;
            break;
        }
    }
    return isPrime;
}

bool GentlemanProtocol::RandomPrimeNumber() {
    for (int i = 0; i < 2; ++i) {
        while (true) {
            PrimeNum[i] = (rand() % (RandPrimeNumInterval[1] - RandPrimeNumInterval[0] + 1)) + RandPrimeNumInterval[0];
            if (PrimeNumberJudgment(PrimeNum[i]) == true) break;
        }
    }

    // Two randomly generated prime numbers cannot be equal;
    if (PrimeNum[0] == PrimeNum[1]) return false;

    return true;
}

bool GentlemanProtocol::KeyPairCalculation() {
    int N = PrimeNum[0] * PrimeNum[1];
    int ETN = (PrimeNum[0] - 1) * (PrimeNum[1] - 1);

    KeyPair.PublicKey[0] = 1;
    KeyPair.PrivateKey[0] = 1;
    KeyPair.PublicKey[1] = N;
    KeyPair.PrivateKey[1] = N;

    /*------------------------------------------------------------
    A PrivateKey must meet three conditions
    1. The integer PrivateKey is in the interval "(1,ETN)"
    2. The PrivateKey is a prime number;
    3. ETN MOD PublicKey != 0 (PrivateKey is not a factor of ETN);
    ------------------------------------------------------------*/
    while (true) {
        // Get random numbers from the interval "(1,ETN)";
        KeyPair.PrivateKey[0] = (rand() % (ETN - 2)) + 2;
        if (PrimeNumberJudgment(KeyPair.PrivateKey[0]) == true && ETN % KeyPair.PrivateKey[0] != 0) break;
    }

    while (true) {
        // The condition that the public key needs to meet is "(PrivateKey * PublicKey) MOD ETN = 1";
        if ((KeyPair.PrivateKey[0] * KeyPair.PublicKey[0]) % ETN == 1) break;
        ++KeyPair.PublicKey[0];  // Excessive from small to large;
    }

    // Public key cannot be equal to private key;
    if (KeyPair.PublicKey[0] == KeyPair.PrivateKey[0]) return false;

    return true;
}

// String to ASCII;
int *GentlemanProtocol::ASCII_EnCoding(String StrInput) {
    StrLength = StrInput.length();

    int *DecOutput = new int[StrLength];
    for (unsigned int i = 0; i < StrLength; ++i) DecOutput[i] = int(StrInput[i]);

    return DecOutput;
}
// ASCII to String;
String GentlemanProtocol::ASCII_DeCoding(int *DecInput) {
    String StrTemp, StrOutput;
    for (unsigned int i = 0; i < StrLength; ++i) {
        StrTemp = DecInput[i];
        StrOutput = StrOutput + StrTemp;
    }
    return StrOutput;
}

void GentlemanProtocol::SetRandRange(int LVALUE, int RVALUE) {
    // The range of values for pseudo-random numbers is set here;
    RandPrimeNumInterval[0] = LVALUE;
    RandPrimeNumInterval[1] = RVALUE;
}

KEYPAIR GentlemanProtocol::GenerateKeyPair() {
    while (true) {                                    // Make sure the two generated prime numbers are not equal and the generated key pair are not equal;
        srand(KeyPair.PublicKey[0] + PrimeNum[0]);    // If they are equal change the random number seed and recalculate until they are not equal;
        if (RandomPrimeNumber() == true)              // The function returns "true" if the two randomly generated prime numbers are not equal;
            if (KeyPairCalculation() == true) break;  // The function returns "true" if the public key and the private key are not equal;
    }

    return KeyPair;
}

// ENC: Cipher = (Origin ^ PublicKey)mod ETN;
String GentlemanProtocol::Encrypt(String Origin_Str, int Key[2]) {
    /*---------------------------------------------------------------------------------------------------------------
    The "Key" here can be either "public key" or "private key", use "public key" encryption for data transmission,
    and use "private key" encryption for digital signature;
    ---------------------------------------------------------------------------------------------------------------*/

    int *DecASCII = ASCII_EnCoding(Origin_Str);  // Text to ASCII encoding;

    /*---------------------------------------------------------------------------------------------------------------
    1. C = m^e mod n;
    2. Cipher = (DecASCII[i]^Key[0]) mod Key[1];
    3. If the above formula is used directly, overflow will definitely occur, so we use its distributive law formula:
       "(a * b) mod n = (a mod n * b mod n) mod n";
    ---------------------------------------------------------------------------------------------------------------*/

    String Cipher_Str;
    for (unsigned int i = 0; i < StrLength; ++i) {
        long long ModTemp = DecASCII[i] % Key[1];
        for (int j = 0; j < Key[0] - 1; ++j) {
            DecASCII[i] = (ModTemp * (DecASCII[i] % Key[1])) % Key[1];
        }
        Cipher_Str = Cipher_Str + String(DecASCII[i]) + ",";
    }

    delete[] DecASCII;
    return Cipher_Str;
}
// DEC: Origin = (Cipher ^ PrivateKey)mod ETN;
String GentlemanProtocol::Decrypt(String Cipher_Str, int Key[2]) {
    /*---------------------------------------------------------------------------------------------------------------
        The "Key" here can be either "public key" or "private key", use "public key" encryption for data transmission,
        and use "private key" encryption for digital signature;
    ---------------------------------------------------------------------------------------------------------------*/

    // Determine the number of Parts according to the number of "," in the string;
    int StrPartNum = std::count(Cipher_Str.begin(), Cipher_Str.end(), ',');
    StrLength = StrPartNum;

    int *Str_Dec = new int[StrPartNum];  // Create a "Str" decimal container;

    /* Slice the string from ","; */
    unsigned int Cipher_Bit = 0, LeftBreakPoint = -1, RightBreakPoint = 0;
    for (unsigned int i = 0; i < Cipher_Str.length(); ++i) {
        /* Extract the characters in the string one by one, when it is equal to ",",
        cut out the string between ["0"~current","] or [previous","~current","] and convert it to "int" type; */
        if (Cipher_Str[i] == ',') {
            RightBreakPoint = i;  // Determine the right breakpoint of the cut out string as the current "," position;

            // Cut out the target string;
            String Cipher_Str_Temp = "";
            for (unsigned int j = LeftBreakPoint + 1; j < RightBreakPoint; ++j) Cipher_Str_Temp = Cipher_Str_Temp + Cipher_Str[j];

            Str_Dec[Cipher_Bit] = atoi(Cipher_Str_Temp.c_str());  // Convert to "int" type;

            LeftBreakPoint = RightBreakPoint;  // breakpoint shift;
            ++Cipher_Bit;                      // "Str" decimal container shift;
        }
    }

    // RSA decryption operation;
    /*---------------------------------------------------------------------------------------------------------------
    2. Origin = (Str_Dec[i]^Key[0]) mod Key[1];5
    3. If the above formula is used directly, overflow will definitely occur, so we use its distributive law formula:
       "(a * b) mod n = (a mod n * b mod n) mod n";
    ---------------------------------------------------------------------------------------------------------------*/
    for (int i = 0; i < StrPartNum; ++i) {
        long long ModTemp = Str_Dec[i] % Key[1];
        for (int j = 0; j < Key[0] - 1; ++j) {
            Str_Dec[i] = (ModTemp * (Str_Dec[i] % Key[1])) % Key[1];
        }
    }

    String DEC_Str = ASCII_DeCoding(Str_Dec);
    delete[] Str_Dec;
    return DEC_Str;
}