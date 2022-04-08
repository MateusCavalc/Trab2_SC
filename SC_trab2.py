import random
import string
import numpy
from Crypto.Util import number

MIN_BITSIZE = 8 # BITS
SIM_KEY_SIZE = 16 # BYTES
KEY_CHARS = string.ascii_uppercase + string.digits # CHARS TO BUILD SIM KEYS
EAS_128 = 128
EAS_192 = 192
EAS_256 = 256

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
                  [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]])

GALOIS_FIELD = [[2, 3, 1, 1],
                [1, 2, 3, 1],
                [1, 1, 2, 3],
                [3, 1, 1, 2]]

INV_GALOIS_FIELD = [[14, 11, 13, 9],
                    [9, 14, 11, 13],
                    [13, 9, 14, 11],
                    [11, 13, 9, 14]]

def lookup(byte):
    x = byte >> 4
    y = byte & 15
    return aes_sbox[x][y]


def reverse_lookup(byte):
    x = byte >> 4
    y = byte & 15
    return reverse_aes_sbox[x][y]

ROUNDS = {EAS_128:10, EAS_192:12, EAS_256:14}

PLAIN_TEXT = "Texto exemplo para cifracao"

def MDC(a, b):
    
    while(b != 0):
        resto = a % b
        a = b
        b = resto

    return a

def Get_N_and_E(bitsize):
    p = number.getPrime(bitsize)
    q = number.getPrime(bitsize)
    
    N = p * q

    Pn = (p-1) * (q-1)
    
    while True:
        E = random.randrange(2, Pn + 1)
        
        if not MDC(Pn, E) == 1: continue
        else:   break
    
    return N, E, Pn

def Get_D(E, Pn):
    D = 0
    
    while True:
        D += 1
        if (E * D) % Pn == 1:
            return D
        
def RSA_encoder(plain, N, E):
    enc = ''
    
    for char in plain:
        enc_char = (ord(char) ** E) % N
        enc += str(enc_char)
        enc += ' '
        
    return enc
    
def RSA_decoder(encoded, N, D):
    dec = ''
    
    enc_blocks = encoded.split()
    
    for block in enc_blocks:
        dec_char = (int(block) ** D) % N
        dec += chr(dec_char)
        
    return dec

def Chaves_assim():
    N, E, Pn = Get_N_and_E(MIN_BITSIZE)
    D = Get_D(E, Pn)
    
    print('N = {}'.format(N))
    print('E = {}'.format(E))    
    print('D = {}'.format(D))
    
    return N, E, D

def Chave_sim(size_bytes):
    return ''.join(random.choice(KEY_CHARS) for _ in range(size_bytes))

def RotWord(word):
    aux_array = numpy.zeros(4)
    
    for j in range(0, 4):
        mapped_j = ((j - 1) + 4) % 4
            
        # print('{} mapped to {}'.format(j, mapped_j))
        aux_array[mapped_j] = word[j]
        
    for j in range(0, 4):
        word[j] = aux_array[j]
 
def SubWord(word):
    for j in range(0, 4):
        word[j] = lookup(word[j])

def AddRoundConst(word, iter):
    curr_round = ROUND_CONSTANT[:,iter]

    word = numpy.add(word, curr_round)

def ExpandKey(key_state, round_count):
    new_key_state = numpy.zeros(shape=(4, 4), dtype=numpy.byte)

    w3 = key_state[:,3]
    RotWord(w3)
    SubWord(w3)
    AddRoundConst(w3, round_count)
    for i, cell in enumerate(key_state[:,0]):
        new_key_state[0][i] = w3[i] ^ cell
    
    

def SubBytes(curr_state, inv=False):
    for j in range(0, 4):
        for i in range(0, 4):
            if not inv:
                curr_state[i][j] = lookup(curr_state[i][j])
            else:
                curr_state[i][j] = reverse_lookup(curr_state[i][j])
    
def ShiftRows(curr_state, inv=False):
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
        
def MixColumns(curr_state, inv=False):
    for j in range(0, 4):
        col = curr_state[:,j]
        
        if not inv:
            new_col = numpy.matmul(GALOIS_FIELD, col)
        else:
            new_col = numpy.matmul(INV_GALOIS_FIELD, col)
        
        for i in range(0, 4):
            curr_state[i][j] = new_col[i]
            
def AddRoundKey(curr_state, key_state):
    for j in range(0, 4):
        for i in range(0, 4):
            curr_state[i][j] = curr_state[i][j] ^ key_state[i][j]
    
def AES_encoder(plain, key):
    encoded = ''
    state = numpy.zeros(shape=(4, 4), dtype=numpy.byte)
    plain_offset = 0
    
    key_state = numpy.zeros(shape=(4, 4), dtype=numpy.byte)
    
    # fill key state with 16 byte key
    count = 0
    for j in range(0, 4):
        for i in range(0, 4):
            key_state[i][j] = ord(key[count])
            count += 1
    
    while plain_offset < len(plain):
        offset_adder = 0
        
        # fill state with 16 characters from plain text
        for j in range(0, 4):
            for i in range(0, 4):
                if plain_offset + offset_adder < len(plain):
                    state[i][j] = ord(plain[plain_offset + offset_adder])
                    offset_adder += 1
                else:
                    break            
            
        plain_offset += offset_adder
        
        # print("Initial state:", state)
          
        # Sequencia de operações
        AddRoundKey(state, key_state)
        
        for n in range(ROUNDS[len(key) * 8] - 1):
            SubBytes(state)
            ShiftRows(state)
            MixColumns(state)
            AddRoundKey(state, key_state)
            
        SubBytes(state)
        ShiftRows(state)
        AddRoundKey(state, key_state)
        
        # print("Final state:", state)
            
        # put final state (16 encoded characters) in encoded string
        for j in range(0, 4):
            for i in range(0, 4):
                encoded += str(state[i][j])
                encoded += ' '
                    
        state.fill(0)
        
    return encoded

def AES_decoder(encoded, key):
    decoded = ''
    state = numpy.zeros(shape=(4, 4), dtype=numpy.byte)
    enc_offset = 0
    
    enc_blocks = encoded.split()
    
    key_state = numpy.zeros(shape=(4, 4), dtype=numpy.byte)
    
    # fill key state with 16 byte key
    count = 0
    for j in range(0, 4):
        for i in range(0, 4):
            key_state[i][j] = ord(key[count])
            count += 1
    
    while enc_offset < len(enc_blocks):
        offset_adder = 0
        
        # fill state with 16 characters from plain text
        for j in range(0, 4):
            for i in range(0, 4):
                if enc_offset + offset_adder < len(enc_blocks):
                    state[i][j] = enc_blocks[enc_offset + offset_adder]
                    offset_adder += 1
                else:
                    break            
            
        enc_offset += offset_adder
        
        print("Initial state:", state)
          
        # Sequencia de operações invertida
        AddRoundKey(state, key_state)
        ShiftRows(state, inv=True)
        SubBytes(state, inv=True)
        
        for n in range(ROUNDS[len(key) * 8] - 1):
            AddRoundKey(state, key_state)
            MixColumns(state, inv=True)
            ShiftRows(state, inv=True)
            SubBytes(state, inv=True)
            
        AddRoundKey(state, key_state)
        
        print("Final state:", state)
            
        # put final state (16 encoded characters) in encoded string
        for j in range(0, 4):
            for i in range(0, 4):
                encoded += chr(state[i][j])
                encoded += ' '
                    
        state.fill(0)
        
    return decoded

if __name__ == '__main__':
    
    print("Plain text:", PLAIN_TEXT)
    
# =============================================================================
#     # RSA cipher
#     print("\n< RSA >")
#     N, E, D = Chaves_assim() 
#     rsa_encoded = RSA_encoder(PLAIN_TEXT, N, E)  
#     print("RSA_encoded:", rsa_encoded)
#     rsa_decoded = RSA_decoder(rsa_encoded, N, D)
#     print("RSA_decoded:", rsa_decoded)
#     print()
# =============================================================================
    
    # EAS cipher
    print("\n< AES >")   
    aes_key = Chave_sim(SIM_KEY_SIZE)
    aes_encoded = AES_encoder(PLAIN_TEXT, aes_key)
    print("AES_encoded:", aes_encoded)
    aes_decoded = AES_decoder(aes_encoded, aes_key)
    print("AES_decoded:", aes_decoded)
