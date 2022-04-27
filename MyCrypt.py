import RabinMiller
import string
import numpy
import hashlib
import random
import copy
import base64

MIN_BITSIZE = 1024 # BITS
SIM_KEY_SIZE = 16 # BYTES
KEY_CHARS = string.ascii_uppercase + string.digits # CHARS TO BUILD SIM KEYS
EAS_128 = 128
EAS_192 = 192
EAS_256 = 256

BUF_SIZE = 65536  # lets read stuff in 64kb chunks!

OAEP_M_SIZE = 64 # OAEP PADDED PLAIN MESSAGE SIZE IN BYTES
OAEP_P_SIZE = 84 # OAEP 'P' SIZE IN BYTES
OAEP_BPEC = 256 # OAEP BYTES PER ENCODED CHAR
OAEP_BPEB = OAEP_BPEC * 52 # OAPE BYTES PER ENCODED BLOCK

aes_sbox = [
    [int('63', 16), int('7c', 16), int('77', 16), int('7b', 16), int('f2', 16), int('6b', 16), int('6f', 16), int('c5', 16), int(
        '30', 16), int('01', 16), int('67', 16), int('2b', 16), int('fe', 16), int('d7', 16), int('ab', 16), int('76', 16)],
    [int('ca', 16), int('82', 16), int('c9', 16), int('7d', 16), int('fa', 16), int('59', 16), int('47', 16), int('f0', 16), int(
        'ad', 16), int('d4', 16), int('a2', 16), int('af', 16), int('9c', 16), int('a4', 16), int('72', 16), int('c0', 16)],
    [int('b7', 16), int('fd', 16), int('93', 16), int('26', 16), int('36', 16), int('3f', 16), int('f7', 16), int('cc', 16), int(
        '34', 16), int('a5', 16), int('e5', 16), int('f1', 16), int('71', 16), int('d8', 16), int('31', 16), int('15', 16)],
    [int('04', 16), int('c7', 16), int('23', 16), int('c3', 16), int('18', 16), int('96', 16), int('05', 16), int('9a', 16), int(
        '07', 16), int('12', 16), int('80', 16), int('e2', 16), int('eb', 16), int('27', 16), int('b2', 16), int('75', 16)],
    [int('09', 16), int('83', 16), int('2c', 16), int('1a', 16), int('1b', 16), int('6e', 16), int('5a', 16), int('a0', 16), int(
        '52', 16), int('3b', 16), int('d6', 16), int('b3', 16), int('29', 16), int('e3', 16), int('2f', 16), int('84', 16)],
    [int('53', 16), int('d1', 16), int('00', 16), int('ed', 16), int('20', 16), int('fc', 16), int('b1', 16), int('5b', 16), int(
        '6a', 16), int('cb', 16), int('be', 16), int('39', 16), int('4a', 16), int('4c', 16), int('58', 16), int('cf', 16)],
    [int('d0', 16), int('ef', 16), int('aa', 16), int('fb', 16), int('43', 16), int('4d', 16), int('33', 16), int('85', 16), int(
        '45', 16), int('f9', 16), int('02', 16), int('7f', 16), int('50', 16), int('3c', 16), int('9f', 16), int('a8', 16)],
    [int('51', 16), int('a3', 16), int('40', 16), int('8f', 16), int('92', 16), int('9d', 16), int('38', 16), int('f5', 16), int(
        'bc', 16), int('b6', 16), int('da', 16), int('21', 16), int('10', 16), int('ff', 16), int('f3', 16), int('d2', 16)],
    [int('cd', 16), int('0c', 16), int('13', 16), int('ec', 16), int('5f', 16), int('97', 16), int('44', 16), int('17', 16), int(
        'c4', 16), int('a7', 16), int('7e', 16), int('3d', 16), int('64', 16), int('5d', 16), int('19', 16), int('73', 16)],
    [int('60', 16), int('81', 16), int('4f', 16), int('dc', 16), int('22', 16), int('2a', 16), int('90', 16), int('88', 16), int(
        '46', 16), int('ee', 16), int('b8', 16), int('14', 16), int('de', 16), int('5e', 16), int('0b', 16), int('db', 16)],
    [int('e0', 16), int('32', 16), int('3a', 16), int('0a', 16), int('49', 16), int('06', 16), int('24', 16), int('5c', 16), int(
        'c2', 16), int('d3', 16), int('ac', 16), int('62', 16), int('91', 16), int('95', 16), int('e4', 16), int('79', 16)],
    [int('e7', 16), int('c8', 16), int('37', 16), int('6d', 16), int('8d', 16), int('d5', 16), int('4e', 16), int('a9', 16), int(
        '6c', 16), int('56', 16), int('f4', 16), int('ea', 16), int('65', 16), int('7a', 16), int('ae', 16), int('08', 16)],
    [int('ba', 16), int('78', 16), int('25', 16), int('2e', 16), int('1c', 16), int('a6', 16), int('b4', 16), int('c6', 16), int(
        'e8', 16), int('dd', 16), int('74', 16), int('1f', 16), int('4b', 16), int('bd', 16), int('8b', 16), int('8a', 16)],
    [int('70', 16), int('3e', 16), int('b5', 16), int('66', 16), int('48', 16), int('03', 16), int('f6', 16), int('0e', 16), int(
        '61', 16), int('35', 16), int('57', 16), int('b9', 16), int('86', 16), int('c1', 16), int('1d', 16), int('9e', 16)],
    [int('e1', 16), int('f8', 16), int('98', 16), int('11', 16), int('69', 16), int('d9', 16), int('8e', 16), int('94', 16), int(
        '9b', 16), int('1e', 16), int('87', 16), int('e9', 16), int('ce', 16), int('55', 16), int('28', 16), int('df', 16)],
    [int('8c', 16), int('a1', 16), int('89', 16), int('0d', 16), int('bf', 16), int('e6', 16), int('42', 16), int('68', 16), int(
        '41', 16), int('99', 16), int('2d', 16), int('0f', 16), int('b0', 16), int('54', 16), int('bb', 16), int('16', 16)]
]

reverse_aes_sbox = [
    [int('52', 16), int('09', 16), int('6a', 16), int('d5', 16), int('30', 16), int('36', 16), int('a5', 16), int('38', 16), int(
        'bf', 16), int('40', 16), int('a3', 16), int('9e', 16), int('81', 16), int('f3', 16), int('d7', 16), int('fb', 16)],
    [int('7c', 16), int('e3', 16), int('39', 16), int('82', 16), int('9b', 16), int('2f', 16), int('ff', 16), int('87', 16), int(
        '34', 16), int('8e', 16), int('43', 16), int('44', 16), int('c4', 16), int('de', 16), int('e9', 16), int('cb', 16)],
    [int('54', 16), int('7b', 16), int('94', 16), int('32', 16), int('a6', 16), int('c2', 16), int('23', 16), int('3d', 16), int(
        'ee', 16), int('4c', 16), int('95', 16), int('0b', 16), int('42', 16), int('fa', 16), int('c3', 16), int('4e', 16)],
    [int('08', 16), int('2e', 16), int('a1', 16), int('66', 16), int('28', 16), int('d9', 16), int('24', 16), int('b2', 16), int(
        '76', 16), int('5b', 16), int('a2', 16), int('49', 16), int('6d', 16), int('8b', 16), int('d1', 16), int('25', 16)],
    [int('72', 16), int('f8', 16), int('f6', 16), int('64', 16), int('86', 16), int('68', 16), int('98', 16), int('16', 16), int(
        'd4', 16), int('a4', 16), int('5c', 16), int('cc', 16), int('5d', 16), int('65', 16), int('b6', 16), int('92', 16)],
    [int('6c', 16), int('70', 16), int('48', 16), int('50', 16), int('fd', 16), int('ed', 16), int('b9', 16), int('da', 16), int(
        '5e', 16), int('15', 16), int('46', 16), int('57', 16), int('a7', 16), int('8d', 16), int('9d', 16), int('84', 16)],
    [int('90', 16), int('d8', 16), int('ab', 16), int('00', 16), int('8c', 16), int('bc', 16), int('d3', 16), int('0a', 16), int(
        'f7', 16), int('e4', 16), int('58', 16), int('05', 16), int('b8', 16), int('b3', 16), int('45', 16), int('06', 16)],
    [int('d0', 16), int('2c', 16), int('1e', 16), int('8f', 16), int('ca', 16), int('3f', 16), int('0f', 16), int('02', 16), int(
        'c1', 16), int('af', 16), int('bd', 16), int('03', 16), int('01', 16), int('13', 16), int('8a', 16), int('6b', 16)],
    [int('3a', 16), int('91', 16), int('11', 16), int('41', 16), int('4f', 16), int('67', 16), int('dc', 16), int('ea', 16), int(
        '97', 16), int('f2', 16), int('cf', 16), int('ce', 16), int('f0', 16), int('b4', 16), int('e6', 16), int('73', 16)],
    [int('96', 16), int('ac', 16), int('74', 16), int('22', 16), int('e7', 16), int('ad', 16), int('35', 16), int('85', 16), int(
        'e2', 16), int('f9', 16), int('37', 16), int('e8', 16), int('1c', 16), int('75', 16), int('df', 16), int('6e', 16)],
    [int('47', 16), int('f1', 16), int('1a', 16), int('71', 16), int('1d', 16), int('29', 16), int('c5', 16), int('89', 16), int(
        '6f', 16), int('b7', 16), int('62', 16), int('0e', 16), int('aa', 16), int('18', 16), int('be', 16), int('1b', 16)],
    [int('fc', 16), int('56', 16), int('3e', 16), int('4b', 16), int('c6', 16), int('d2', 16), int('79', 16), int('20', 16), int(
        '9a', 16), int('db', 16), int('c0', 16), int('fe', 16), int('78', 16), int('cd', 16), int('5a', 16), int('f4', 16)],
    [int('1f', 16), int('dd', 16), int('a8', 16), int('33', 16), int('88', 16), int('07', 16), int('c7', 16), int('31', 16), int(
        'b1', 16), int('12', 16), int('10', 16), int('59', 16), int('27', 16), int('80', 16), int('ec', 16), int('5f', 16)],
    [int('60', 16), int('51', 16), int('7f', 16), int('a9', 16), int('19', 16), int('b5', 16), int('4a', 16), int('0d', 16), int(
        '2d', 16), int('e5', 16), int('7a', 16), int('9f', 16), int('93', 16), int('c9', 16), int('9c', 16), int('ef', 16)],
    [int('a0', 16), int('e0', 16), int('3b', 16), int('4d', 16), int('ae', 16), int('2a', 16), int('f5', 16), int('b0', 16), int(
        'c8', 16), int('eb', 16), int('bb', 16), int('3c', 16), int('83', 16), int('53', 16), int('99', 16), int('61', 16)],
    [int('17', 16), int('2b', 16), int('04', 16), int('7e', 16), int('ba', 16), int('77', 16), int('d6', 16), int('26', 16), int(
        'e1', 16), int('69', 16), int('14', 16), int('63', 16), int('55', 16), int('21', 16), int('0c', 16), int('7d', 16)]
]

ROUND_CONSTANT = numpy.array([[0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36],
                  [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                  [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                  [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]], dtype='<u1')

GALOIS_FIELD = numpy.array([[2, 3, 1, 1],
                            [1, 2, 3, 1],
                            [1, 1, 2, 3],
                            [3, 1, 1, 2]], dtype='<u1')

INV_GALOIS_FIELD = numpy.array([[14, 11, 13, 9],
                                [9, 14, 11, 13],
                                [13, 9, 14, 11],
                                [11, 13, 9, 14]], dtype='<u1')

ROUNDS = {EAS_128:10, EAS_192:12, EAS_256:14}

def AddPadding(block):
    M = copy.deepcopy(block)
    while len(M) < OAEP_M_SIZE:
        M += chr(0x00)

    return M

def xor(a, b):
    result = b''
    # print("a:", a, len(a))
    # print("b:", b.hex(), len(b))

    for a_byte, b_byte in zip(a, b):
        # print(hex(a_byte), hex(b_byte), hex(a_byte ^ b_byte))
        try:   
            result += (a_byte ^ b_byte).to_bytes(1, byteorder='little')
        except:
            result += (a_byte ^ b_byte).item().to_bytes(1, byteorder='little')

    return result

def lookup(byte):
    x = byte >> 4
    y = byte & 15
    return aes_sbox[x][y]

def reverse_lookup(byte):
    x = byte >> 4
    y = byte & 15
    return reverse_aes_sbox[x][y]

def gmul(b, a):
    """
    Multiplication in GF(2^8).
    :param int a: operand
    :param int b: another operand
    :return: a•b over GF(2^8)
    :rtype: int
    ref: https://en.wikipedia.org/wiki/Finite_field_arithmetic
    """
    # modified peasant's algorithm
    p = 0
    while a and b:
        # each iteration has that `a•b + p` is the product
        if b & 0x1:
            p ^= a
        carry = a & 0x80  # the leftmost bit of a
        a <<= 1
        if carry:
            a ^= 0x11b  # sub 0b1_0001_1011, a.k.a. the irreducible polynomial x^8+x^4+x^3+x^1+1
        b >>= 1
    return p

def mat_mult(a, b):
    result = numpy.zeros(4, dtype='<u1')

    for i in range(0, 4):
        for j in range(0, 4):
            result[i] = result[i] ^ gmul(b[j], a[i][j])

    return result

def findModInverse(a, m):
    # Returns the modular inverse of a % m, which is
    # the number x such that a*x % m = 1

    def gcd(a, b):
        # Return the GCD of a and b using Euclid's Algorithm
        while a != 0:
            a, b = b % a, a
        return b

    if gcd(a, m) != 1:
        return None # no mod inverse if a & m aren't relatively prime

    # Calculate using the Extended Euclidean Algorithm:
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3 # // is the integer division operator
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m

def MDC(a, b):
    
    while(b != 0):
        resto = a % b
        a = b
        b = resto

    return a

def byte_length(i):
    return (i.bit_length() + 7) // 8

class RSA_OAEP():
    @staticmethod
    def DoHash(toHash, fromFile=False): # SHA3-256 (return HEX)
        sha3 = hashlib.sha3_256()
        file_bytes = b''
        hashed_file = ''

        try:
            if fromFile:
                with open(toHash, 'rb') as f:
                    while True:
                        data = f.read(BUF_SIZE)
                        if not data:    break
                        file_bytes += data
                        sha3.update(data)
            else:
                sha3.update(toHash)

            hashed_file = sha3.hexdigest()
        except Exception as e:
            print(e)

        return file_bytes, hashed_file

    @classmethod
    def Get_N_and_E(self, key_size):
        p = RabinMiller.generateLargePrime(key_size)
        q = RabinMiller.generateLargePrime(key_size)

        print('done')
        
        N = p * q

        Pn = (p-1) * (q-1)
        
        while True:
            E = random.randrange(2 ** (key_size - 1), 2 ** (key_size))
            if MDC(Pn, E) == 1: break
        
        return N, E, Pn

    @classmethod
    def Generate_Key_Pair(self, key_size):
        N, E, Pn = self.Get_N_and_E(key_size)
        print('N = {}'.format(hex(N)))
        print('E = {}'.format(hex(E)))
        
        D = findModInverse(E, Pn)
        print('D = {}'.format(hex(D)))

        public_key = (E, N)
        private_key = (D, N)
            
        return public_key, private_key

    @staticmethod
    def RSA_OAEP_encoder(plain, private_key): # Return plain encoded BASE64
        print('\n[RSA_OAEP] Encoding \'{}\' with private key ({}, {}) ...\n'.format(plain, hex(private_key[0]), hex(private_key[1])))

        E = private_key[0]
        N = private_key[1]

        sha512 = hashlib.sha3_512()
        r = numpy.random.randint(2, size=(20,))
        r = bytes(r.tolist())
        # print("r:", r, len(r))
        sha512.update(r)
        G = sha512.digest() # G = 64 bytes
        # print("hashed_r:", G.hex())
            
        sha1 = hashlib.sha1()
        M = AddPadding(plain) # M = 64 bytes
        # print("M:", M)
        P1 = xor(M.encode(), G)
        sha1.update(P1)
        H = sha1.digest() # H = 20 bytes
        P2 = xor(r, H) # P2 = 20 bytes
        # print("G:", G.hex(), len(G))
        # print("H:", H.hex(), len(H))
        # print("P1:", P1.hex(), len(P1))
        # print("P2:", P2.hex(), len(P2))
        P = P1 + P2 # P = 84 BYTES

        enc_P = pow(int.from_bytes(P, byteorder='big'), E, N)
        # print('P: {} {}'.format(P.hex(), len(P)))
        # print('enc_P: {} {}'.format(hex(enc_P), byte_length(enc_P)))
        # print(enc_b.to_bytes(2, byteorder='big'))
        enc_bytes = enc_P.to_bytes(OAEP_BPEC, byteorder='big')
        base64_enc = base64.b64encode(enc_bytes)
        # print("> BASE64 encoded:", base64_enc.decode('ascii'))

        return  base64_enc.decode('ascii')

    @staticmethod
    def RSA_OAEP_decoder(encoded_base64, public_key): # Input encoded BASE64
        print('\n[RSA_OAEP] Decoding \'{}\' with public key ({}, {}) ...\n'.format(encoded_base64, hex(public_key[0]), hex(public_key[1])))

        dec = b''

        D = public_key[0]
        N = public_key[1]
            
        sha1 = hashlib.sha1()
        sha512 = hashlib.sha3_512()

        encoded_bytes = base64.b64decode(encoded_base64.encode('ascii'))
        decoded_P = pow(int.from_bytes(encoded_bytes, byteorder='big'), D, N)
        P = decoded_P.to_bytes(OAEP_P_SIZE, byteorder='big')

        # print('P: {} {}'.format(P.hex(), len(P)))

        P1 = P[:OAEP_M_SIZE]
        P2 = P[OAEP_M_SIZE:]

        sha1.update(P1)
        H = sha1.digest()
        r = xor(P2, H)
        # print("r(?):", r)
        sha512.update(r)
        G = sha512.digest()

        # print("G:", G.hex(), len(G))
        # print("H:", H.hex(), len(H))
        # print("P1:", P1.hex(), len(P1))
        # print("P2:", P2.hex(), len(P2))

        M = xor(P1, G)
        dec += M.rstrip(b'\x00')
            
        return dec.decode()

class AES():
    @classmethod
    def RotWord(self, word):
        aux_array = numpy.zeros(4)
        
        for j in range(0, 4):
            mapped_j = ((j - 1) + 4) % 4
                
            # print('{} mapped to {}'.format(j, mapped_j))
            aux_array[mapped_j] = word[j]
            
        for j in range(0, 4):
            word[j] = aux_array[j]

    @classmethod
    def SubWord(self, word):
        for j in range(0, 4):
            word[j] = lookup(word[j])

    @classmethod
    def AddRoundConst(self, word, iter):
        curr_round = ROUND_CONSTANT[:,iter]

        for i in range(0, 4):
            word[i] = word[i] ^ curr_round[i]

    @classmethod
    def ExpandKey(self, key_state, round_count):
        new_key_state = numpy.zeros(shape=(4, 4), dtype=numpy.byte)

        w3 = copy.deepcopy(key_state[:,3]) # TODO
        # print('w3:\n{}'.format(w3))
        self.RotWord(w3)
        # print('w3(rotword):\n{}'.format(w3))
        self.SubWord(w3)
        # print('w3(subword):\n{}'.format(w3))
        self.AddRoundConst(w3, round_count)
        # print('w3(addroundconst):\n{}'.format(w3))

        # Perform w4
        for i, cell in enumerate(key_state[:,0]):
            new_key_state[i][0] = w3[i] ^ cell
        
        # Perform w5, w6, w7
        for i in range(0, 3):
            w_aux = new_key_state[:,i]

            for j, cell in enumerate(key_state[:,i+1]):
                # print(hex(w_aux[j] & 0xff), hex(cell & 0xff), hex((w_aux[j] ^ cell) & 0xff))
                new_key_state[j][i+1] = w_aux[j] ^ cell

        # Update key state with new key state
        for i in range(0, 4):
            for j in range(0, 4):
                key_state[i][j] = new_key_state[i][j]

    @classmethod
    def SubBytes(self, curr_state, inv=False):
        for j in range(0, 4):
            for i in range(0, 4):
                if not inv:
                    curr_state[i][j] = lookup(curr_state[i][j])
                else:
                    curr_state[i][j] = reverse_lookup(curr_state[i][j])

    @classmethod       
    def ShiftRows(self, curr_state, inv=False):
        aux_array = numpy.zeros(4)

        for i in range(1, 4):
            for j in range(0, 4):
                if not inv:
                    mapped_j = ((j - i) + 4) % 4
                else:
                    mapped_j = ((j + i) + 4) % 4
                    
                # print('{} mapped to {}'.format(j, mapped_j))
                aux_array[mapped_j] = curr_state[i][j]
                
            for j in range(0, 4):
                curr_state[i][j] = aux_array[j]

    @classmethod
    def MixColumns(self, curr_state, inv=False):
        for j in range(0, 4):
            col = curr_state[:,j]

            if not inv:
                new_col = mat_mult(GALOIS_FIELD, col)
            else:
                new_col = mat_mult(INV_GALOIS_FIELD, col)

            for i in range(0, 4):
                curr_state[i][j] = new_col[i]

    @classmethod
    def AddRoundKey(self, curr_state, key_state):
        for j in range(0, 4):
            for i in range(0, 4):
                curr_state[i][j] = curr_state[i][j] ^ key_state[i][j]

    @classmethod
    def ComputeKeyBlocks(self, key, rounds):
        keys = []
        round_count = 0

        key_state = numpy.zeros(shape=(4, 4), dtype='<u1')

        # fill key state with 16 byte key
        count = 0
        for j in range(0, 4):
            for i in range(0, 4):
                key_state[i][j] = key[count]
                count += 1

        keys.append(copy.deepcopy(key_state))

        for i in range(0, rounds):
            self.ExpandKey(key_state, round_count)
            keys.append(copy.deepcopy(key_state))
            round_count += 1

        return keys

    @classmethod
    def Generate_Key(self, size_bytes):
        return ''.join(random.choice(KEY_CHARS) for _ in range(size_bytes))

    @classmethod
    def Encode(self, plain, keys):
        encoded = b''
        state = numpy.zeros(shape=(4, 4), dtype='<u1')
        plain_offset = 0
        
        while plain_offset < len(plain):
            offset_adder = 0
            
            # fill state with 16 characters from plain text
            for j in range(0, 4):
                for i in range(0, 4):
                    if plain_offset + offset_adder < len(plain):
                        state[i][j] = plain[plain_offset + offset_adder]
                        offset_adder += 1
                    else:
                        break
                
            plain_offset += offset_adder

            round_count = 1

            key_state = keys[0]
            
            # Sequencia de operações
            self.AddRoundKey(state, key_state)
            
            for n in range(1, len(keys) - 1):
                self.SubBytes(state)
                self.ShiftRows(state)
                self.MixColumns(state)
                key_state = keys[round_count]
                self.AddRoundKey(state, key_state)
                round_count += 1
                
            self.SubBytes(state)
            self.ShiftRows(state)
            key_state = keys[round_count]
            self.AddRoundKey(state, key_state)
            
            encoded += state.transpose().tobytes()
                        
            state.fill(0)
            
        return encoded

    @classmethod
    def Decode(self, encoded, keys):
        decoded = b''
        state = numpy.zeros(shape=(4, 4), dtype='<u1')
        enc_offset = 0
        
        while enc_offset < len(encoded):
            offset_adder = 0
            
            # fill state with 16 characters from plain text
            for j in range(0, 4):
                for i in range(0, 4):
                    if enc_offset + offset_adder < len(encoded):
                        state[i][j] = encoded[enc_offset + offset_adder]
                        offset_adder += 1
                    else:
                        break
                
            enc_offset += offset_adder

            round_count = 9

            key_state = keys[len(keys) - 1]
            
            # Sequencia de operações invertida
            self.AddRoundKey(state, key_state)
            self.ShiftRows(state, inv=True)
            self.SubBytes(state, inv=True)
            
            for n in range(1, len(keys) - 1):
                key_state = keys[round_count]
                self.AddRoundKey(state, key_state)
                self.MixColumns(state, inv=True)
                self.ShiftRows(state, inv=True)
                self.SubBytes(state, inv=True)
                round_count -= 1
            
            key_state = keys[0]
            self.AddRoundKey(state, key_state)
            
            decoded += state.transpose().tobytes()
                        
            state.fill(0)
            
        return decoded.rstrip(b'\x00')

class AES_CTR():
    # Constructor
    def __init__(self):
        self.keyBlocks = None
        self.nonce = None

    def ComputeKeyBlocks(self, key):
        rounds = ROUNDS[len(key) * 8]
        self.keyBlocks = AES.ComputeKeyBlocks(key.encode('utf-8'), rounds)

    def SetNonce(self, nonce):
        self.nonce = nonce

    def Encode(self, plain=None, filename=None):
        if self.keyBlocks is None:  raise NoKeyBlocks
        elif self.nonce is None:  raise NoNonce

        encoded = b''
        plain_state = b''
        plain_offset = 0
        counter = 0 # Counter used with nonce

        if plain: # Codifica mensagem plain
            while plain_offset < len(plain):
                offset_adder = 0

                while offset_adder < 16:
                    # fill plain_state with 16 characters from plain text
                    if plain_offset + offset_adder < len(plain):
                        plain_state += bytes(plain[plain_offset + offset_adder], 'utf-8')
                        offset_adder += 1
                    else:
                        break

                if len(plain_state) < 16:
                    while len(plain_state) < 16:
                        plain_state += b'\x00'
                    
                plain_offset += offset_adder

                to_AES = self.nonce + counter.to_bytes(8, byteorder='big') # to_aes 128 bits
                enc_counter = AES.Encode(to_AES, self.keyBlocks)
                encoded += xor(enc_counter, plain_state)
                counter += 1       
                plain_state = b''

        elif filename: # Codifica arquivo
            data = None
            try:
                with open(filename, 'rb') as f:
                    while True:
                        while len(file_bytes) < 16:
                            data = f.read(BUF_SIZE)
                            if not data:    break
                            plain_state += data

                        if len(plain_state) < 16:
                            while len(plain_state) < 16:
                                plain_state += b'\x00'

                        to_AES = self.nonce + counter.to_bytes(8, byteorder='big') # to_aes 128 bits
                        enc_counter = AES.Encode(to_AES, self.keyBlocks)
                        encoded += xor(enc_counter, plain_state)
                        if not data:    break
                        counter += 1
                        plain_state = b''

            except Exception as e:
                print(e)

        return encoded

    def Decode(self, encoded):
        if self.keyBlocks is None:  raise NoKeyBlocks
        elif self.nonce is None:  raise NoNonce

        plain = b''
        encoded_state = b''
        encoded_offset = 0
        counter = 0 # Counter used with nonce
        
        while encoded_offset < len(encoded):
            offset_adder = 0

            while offset_adder < 16:
                # fill encoded_state with 16 characters from encoded text
                if encoded_offset + offset_adder < len(encoded):
                    encoded_state += encoded[encoded_offset + offset_adder].to_bytes(1, byteorder='big')
                    offset_adder += 1
                else:
                    break
                
            encoded_offset += offset_adder

            to_AES = self.nonce + counter.to_bytes(8, byteorder='big') # to_aes 128 bits
            
            enc_counter = AES.Encode(to_AES, self.keyBlocks)
            
            plain += xor(enc_counter, encoded_state)
                        
            encoded_state = b''

        return plain.rstrip(b'\x00').decode()



class NoKeyBlocks(Exception):
    pass

class NoNonce(Exception):
    pass