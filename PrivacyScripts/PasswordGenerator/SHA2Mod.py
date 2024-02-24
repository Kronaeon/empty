K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]


class SHA:
    def __init__(self, constant, data: bytearray) -> bytearray:
        self.message = data
        self.blocks = [] #contains 512-bit chunks of message
        self.m_sched = []

        # The Original Hash Values
        self.hashes = [
            0x6A09E667,
            0xBB67AE85,
            0x3C6EF372,
            0xA54FF53A,
            0x510E527F,
            0x9B05688C,
            0x1F83D9AB,
            0x5BE0CD19,
        ]
        self.constantHex = constant

        self.wrapperSHA()
        #print(self.constantHex)

    def wrapperSHA(self):
        self.initialCheck()
        self.paddingMessage()
        self.parsing()

    def initialCheck(self):
        if isinstance(self.message, str):
            self.message = bytearray(self.message, 'ascii')
        elif isinstance(self.message, bytes):
            self.message = bytearray(self.message)
        elif not isinstance(self.message, bytearray):
            raise TypeError
    
    def paddingMessage(self):
        # Padding
        length = len(self.message) * 8 # len(message) is number of BYTES!!!
        self.message.append(0x80)
        while (len(self.message) * 8 + 64) % 512 != 0:
            self.message.append(0x00)
        self.message += length.to_bytes(8, 'big') # pad to 8 bytes or 64 bits
        assert (len(self.message) * 8) % 512 == 0, "Padding did not complete properly!"
    
    def parsing(self):
        for i in range(0, len(self.message), 64): # 64 bytes is 512 bits
            self.blocks.append(self.message[i:i+64])
    
    def SHA_Hash_Computation(self):
        # here we calc sha hash.
        for m_block in self.blocks:
            # m_sched = []
            for t in range(0, 64):
                if t <= 15:
                    # adds the t'th 32 bit word of the block,
                    # starting from leftmost word
                    # 4 bytes at a time
                    self.m_sched.append(bytes(m_block[t*4:(t*4)+4]))
                else:
                    term1 = _sigma1(int.from_bytes(self.m_sched[t-2], 'big'))
                    term2 = int.from_bytes(self.m_sched[t-7], 'big')
                    term3 = _sigma0(int.from_bytes(self.m_sched[t-15], 'big'))
                    term4 = int.from_bytes(self.m_sched[t-16], 'big')

                    # append a 4-byte byte object
                    schedule = ((term1 + term2 + term3 + term4) % 2**32).to_bytes(4, 'big')
                    self.m_sched.append(schedule)

            #assert len(self.m_sched) == 64

            self.iterForConstants()

            # for i, y_hex in enumerate(self.hashes):
            #     exec(f"h{i} = {y_hex}")
        resultBytes = self.hashes[0].to_bytes(4, 'big')
        for zterator in range (2, len(self.hashes)):
            resultBytes += (self.hashes[zterator]).to_bytes(4, 'big')

        return resultBytes

    def iterForConstants(self):
        # for i, priHex in enumerate(self.hashes):
        #     exec(f"{chr(97 + i)} = {priHex}") #a, b, c, d, e, f, g, h = self.hashes
        # workVarList = []
        # for i, priHex in enumerate(self.hashes):
        #     variable_name = chr(97 + i)
        #     workVarList.append({variable_name: priHex})
        a, b, c, d, e, f, g, h = self.hashes

        for t in range(len(self.constantHex)):
            t1 = ((h + _capsigma1(e) + _ch(e, f, g) + self.constantHex[t] +
                   int.from_bytes(self.m_sched[t], 'big')) % 2**32)

            t2 = (_capsigma0(a) + _maj(a, b, c)) % 2**32

            h = g
            g = f
            f = e
            e = (d + t1) % 2**32
            d = c
            c = b
            b = a
            a = (t1 + t2) % 2**32

        self.comIterHash([a, b, c, d, e, f, g, h]) # workVarList = [a, b, c, d, e, f, g, h]
    
    def comIterHash(self, workVarList):
        for i in range(len(self.hashes)):
            self.hashes[i] = ((self.hashes[i] + workVarList[i]) % 2**32)


def _sigma0(num: int):
    num = (ROTRn_Right(num, 7) ^
           ROTRn_Right(num, 18) ^
           (num >> 3))
    return num

def _sigma1(num: int):
    num = (ROTRn_Right(num, 17) ^
           ROTRn_Right(num, 19) ^
           (num >> 10))
    return num

def _capsigma0(num: int):
    num = (ROTRn_Right(num, 2) ^
           ROTRn_Right(num, 13) ^
           ROTRn_Right(num, 22))
    return num

def _capsigma1(num: int):
    num = (ROTRn_Right(num, 6) ^
           ROTRn_Right(num, 11) ^
           ROTRn_Right(num, 25))
    return num

def _ch(x: int, y: int, z: int):
    return (x & y) ^ (~x & z)

def _maj(x: int, y: int, z: int):
    return (x & y) ^ (x & z) ^ (y & z)

def ROTRn_Right(num: int, shift: int, size: int = 32):
    return (num >> shift) | (num << size - shift)


if __name__ == "__main__":
    print("\n")
    c = SHA(K, ("ThomasKelemvoris"))
    print(c.SHA_Hash_Computation().hex(), "\n")
        

