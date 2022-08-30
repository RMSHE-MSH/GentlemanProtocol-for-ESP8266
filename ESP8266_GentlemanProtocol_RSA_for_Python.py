import random


class ESP8266RSA:
    KeyPair = {'PublicKey': 1, 'PrivateKey': 1, 'KeyN': 0}

    RandPrimeNumInterval = [32, 128]
    PrimeNum = ()
    StrLength = None

    @staticmethod
    def PrimeNumberJudgment(num):
        isPrime = True
        for i in range(2, num):
            if (num % i) == 0:
                isPrime = False
                break
        return isPrime

    def RandomPrimeNumber(self):
        while True:
            self.PrimeNum = (
                random.randint(self.RandPrimeNumInterval[0], self.RandPrimeNumInterval[1]),
                random.randint(self.RandPrimeNumInterval[0], self.RandPrimeNumInterval[1]))

            if self.PrimeNum[0] != self.PrimeNum[1]:
                if self.PrimeNumberJudgment(self.PrimeNum[0]) and self.PrimeNumberJudgment(RSA.PrimeNum[1]) == True:
                    break
        return True

    def KeyPairCalculation(self):
        N = self.PrimeNum[0] * self.PrimeNum[1]
        ETN = (self.PrimeNum[0] - 1) * (self.PrimeNum[1] - 1)

        self.KeyPair['KeyN'] = N

        while True:
            while True:
                self.KeyPair['PrivateKey'] = random.randint(2, ETN - 1)
                if self.PrimeNumberJudgment(self.KeyPair['PrivateKey']) and ETN % self.KeyPair['PrivateKey'] != 0:
                    break

            while True:
                if self.KeyPair['PrivateKey'] * self.KeyPair['PublicKey'] % ETN == 1:
                    break
                self.KeyPair['PublicKey'] += 1

            if self.KeyPair['PrivateKey'] != self.KeyPair['PublicKey']:
                break

        pass

    def ASCII_EnCoding(self, StrInput):
        DecOutput = []
        self.StrLength = len(StrInput)
        for i in StrInput:
            DecOutput.append(ord(i))
        return DecOutput

    def ASCII_DeCoding(self, DecInput):
        StrOutput = ""
        for i in DecInput:
            StrOutput = StrOutput + chr(i)
        return StrOutput

    def SetRandRange(self, LVALUE, RVALUE):
        self.RandPrimeNumInterval[0] = LVALUE
        self.RandPrimeNumInterval[1] = RVALUE

    def GenerateKeyPair(self):
        self.RandomPrimeNumber()
        self.KeyPairCalculation()
        return self.KeyPair

    def Encrypt(self, Origin_Str, Key):
        DecASCII = self.ASCII_EnCoding(Origin_Str)

        Cipher_Str = ""
        for i in range(self.StrLength):
            ModTemp = DecASCII[i] % Key['KeyN']
            for j in range(Key['PublicKey'] - 1):
                DecASCII[i] = (ModTemp * (DecASCII[i] % Key['KeyN'])) % Key['KeyN']
            Cipher_Str = Cipher_Str + str(DecASCII[i]) + ","

        return Cipher_Str

    def Decrypt(self, Cipher_Str, Key):
        StrPartNum = Cipher_Str.count(",")
        self.StrLength = StrPartNum

        Cipher_Bit = 0
        LeftBreakPoint = -1
        RightBreakPoint = 0

        Str_Dec = []
        for i in range(len(Cipher_Str)):
            if Cipher_Str[i] == ',':
                RightBreakPoint = i

                Cipher_Str_Temp = ""
                for j in range(LeftBreakPoint + 1, RightBreakPoint):
                    Cipher_Str_Temp = Cipher_Str_Temp + Cipher_Str[j]

                Str_Dec.append(int(Cipher_Str_Temp))

                LeftBreakPoint = RightBreakPoint
                Cipher_Bit += 1

        for i in range(StrPartNum):
            ModTemp = Str_Dec[i] % Key['KeyN']
            for j in range(Key['PrivateKey'] - 1):
                Str_Dec[i] = (ModTemp * (Str_Dec[i] % Key['KeyN'])) % Key['KeyN']

        return self.ASCII_DeCoding(Str_Dec)


RSA = ESP8266RSA()
RSA.RandomPrimeNumber()
RSA.KeyPairCalculation()
print("PublicKey:", RSA.KeyPair['PublicKey'], "; PrivateKey:", RSA.KeyPair['PrivateKey'], "; KeyN:", RSA.KeyPair['KeyN'])

Cipher_Str = RSA.Encrypt("GOD'S IN HIS HEAVEN. ALL'S RIGHT WITH THE WORLD.", RSA.KeyPair)
print("Cipher_Str:", Cipher_Str)

Origin_Str = RSA.Decrypt(Cipher_Str, RSA.KeyPair)
print("Origin_Str:", Origin_Str)
