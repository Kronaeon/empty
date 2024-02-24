# -----==<>==<>==<>==<>==<>==<>==<>==<>==<>==<>==<>==<>==-----
# Author: (Kronaeon) Matthew A. Dean
# Created: 02/21/24
# Euclid's.Very.Annoying.Cipher - 21 Primes
# Version: 1.0
# -----==<>==<>==<>==<>==<>==<>==<>==<>==<>==<>==<>==<>==-----

# Last Update: 02/23/24
# LU, by: 


import SHA2Mod as SHash

EuclidPrimes = [0x602e51d5, 0xcdd91b9d, 0x87d7f6e1, 
                0xa589e6f9, 0xb2b8e5fd, 0x4b333ae6, 
                0x673d5aa8, 0xcd103052, 0xe41542b2, 
                0x4b676dad, 0x80226564, 0x6ec4fa01, 
                0xb7bdf60, 0x1be0c2fb, 0x2f887db2, 
                0x3ca03be5, 0x4cfad582, 0x74f2f615, 
                0xd537bc5, 0x4b2ed7a6, 0xfc64ddbd]

cipherHead = ("The word is Rome's and the Gods gave it to Caesar;"
                "Caesar is the descendant of the Gods, and a God."
                "He who never lost a battle is to every soldier a father."
                "He has planted his heel on the mouth of the rich man,"
                "But to the poor he is a friend and a consoler."
                "By this you know that the Gods love Rome:"
                "They have given it to Caesar, their descendant and a God.")

def cStrings(username, primaryKey, website, kyfer):
    stri = username + str(kyfer) + website + str(primaryKey) + str(cipherHead) # the Kyfer is a shift bit. essentially it's just a (2^11 + ) incrament as you lose passwords, please only select Euclid Primes.
    return stri

def printSteps(c, _c):
    print("Step 1, SHA-256: ", _c, "\n")
    print("Step 2, EVAC-21: ", c, "\n")

def encryptIT(c, num):
    c = SHash.SHA(SHash.K, c)
    c = c.SHA_Hash_Computation().hex()
    _c = c
    c = SHash.SHA(EuclidPrimes, c)
    c = c.SHA_Hash_Computation().hex()
    
    if(num == 1):
        printSteps(c, _c)

    return c

def strongPassword(delta):
    prtsOfStri = splitACharString(delta) #a, b, c, d = prtsOfStri # we use b and d to put symbols into.  #symbolDict = {smallItem:small for smallItem in bigList}
    prtsOfStri = strengthenString(prtsOfStri)
    striHalfed = []
    
    for i in range(len(prtsOfStri)):
        striHalfed.append(cutStringinHalf(prtsOfStri[i])) # prtsOfStri = [cutStringinHalf(char) for char in prtsOfStri] # we need to make the password smaller, so we reduce the length from 256, to 128 bits long.
    
    epsilon = ''.join(striHalfed) # now I put it all back together into a single string, epsilon. this has 128 bits of a passcode.
    #print("128 code: ", epsilon, "\n")
    return epsilon


def cutStringinHalf(stri2):
    mid = len(stri2) // 2
    return stri2[mid:] # this grabs only the second part of the string. the password is too long right now. 

def splitACharString(stri):
    n = 16 # 64/4 = 16
    prtsOfStri = [stri[i:i+n] for i in range (0, len(stri), n)] # this splits the string 'stri' into N equal parts, using list comprehension. based on the length.
    #a, b, c, d = prtsOfStri # we use b and d to put symbols into.  #symbolDict = {smallItem:small for smallItem in bigList}
    return prtsOfStri


def strengthenString(prtsOfStri):
    symlist = list(r'!$*-#&?){.')
    symbolDictionary = dict(map(lambda x: (str(x[0]), x[1]), enumerate(symlist)))
    symbolDictRev = {key: value[::-1] for key, value in symbolDictionary.items()}
    def symbolize(striPart_abcd, symbolDict):
        for key, value in symbolDict.items():
            striPart_abcd = striPart_abcd.replace(key, value)
        return striPart_abcd
    
    def capitalize(striPart_abcd):
        return striPart_abcd.upper()

    for i in range(len(prtsOfStri)):
        if i % 2 == 0: # check if the iterator is even. 
            prtsOfStri[i] = capitalize(prtsOfStri[i])
        else:
            if(prtsOfStri == 'b'):
                prtsOfStri[i] = symbolize(prtsOfStri[i], symbolDictionary)
            else: prtsOfStri[i] = symbolize(prtsOfStri[i], symbolDictRev)

    return prtsOfStri
    


def generateMultiLenPasscodes(stri, passwordLength): # create passwords of length 20, 16, 12, 8, and 4 bits (passwordLength is the desired length)
    n = (len(stri) - passwordLength) // 2
    DesiredLength_PC = stri[n:-n]
    psLengthsList = [4, 8, 12, 16, 20]
    flag = 0
    for i in range(len(psLengthsList)):
        nm = (len(stri) - psLengthsList[i]) // 2
        if passwordLength == psLengthsList[i]:
            flag = 1
        print(psLengthsList[i], " Character Long Passcode: ", stri[nm:-nm], "\n")
    if flag == 0:
        print(passwordLength, " Desired Length Long passcode: ", DesiredLength_PC, "\n")




def Overture(username, primaryKey, website, kyfer, i, outputSteps, passwordLength):
    print("username: ", username, "\n", "website: ", website, "\n", "current kyfer: ", i, "\n")
    initialString = cStrings(username, primaryKey, website, kyfer)
    hexedHashWord = encryptIT(initialString, outputSteps) # outputSteps = num for the function, 1=true, 0=false
    epsilon = strongPassword(hexedHashWord) # for future use, but regardless it will print out the password.
    print("EVAC-21 SCRAMBLE (PASSCODE Default 28 characters Long): ", epsilon, "\n")
    if passwordLength != 28:
        generateMultiLenPasscodes(epsilon, passwordLength)
    #strongPassword(hexedHashWord)



if __name__ == "__main__":
    print("Password Generator: \n")
    
    # ----// User block //----
    username = "JediDean"
    primaryKey = "aluminiumfalcon"
    website = "twitter"
    i = 11
    kyfer = (2**i)
    passwordLength = 26 # default length == 28, change if you'd like
    # ----// End of user block // ---

    # ----// Debug block //----
    outputSteps = 0 # if you want to see the individual steps of SHA-256, and EVAC-21's outputs. change this value to 1. otherwise ignore.
    # ----// End of Debug block //----

    Overture(username, primaryKey, website, kyfer, i, outputSteps, passwordLength)
    # -- Overture -- #
    # print("username: ", username, "\n", "website: ", website, "\n", "current kyfer: ", i, "\n")
    # initialString = cStrings(username, primaryKey, website, kyfer)
    # hexedHashWord = encryptIT(initialString) #print(hexedHashWord, "\n")
    # epsilon = strongPassword(hexedHashWord)
    # -- Overture -- #



