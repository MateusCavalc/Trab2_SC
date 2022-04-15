import random
import string
import numpy
import copy
from Crypto.Util import number
import hashlib
import base64
from sys import getsizeof, argv
from http.server import BaseHTTPRequestHandler, HTTPServer
import http.client
import json

MIN_BITSIZE = 8 # BITS
SIM_KEY_SIZE = 16 # BYTES
KEY_CHARS = string.ascii_uppercase + string.digits # CHARS TO BUILD SIM KEYS
EAS_128 = 128
EAS_192 = 192
EAS_256 = 256

BUF_SIZE = 65536  # lets read stuff in 64kb chunks!

MAX_BLOCK_SIZE = 30
OAEP_M_SIZE = 32
OAEP_K_SIZE = 80

OAEP_BPEC = 2 # OAEP BYTES PER ENCODED CHAR
OAEP_BPEB = 104 # OAPE BYTES PER ENCODED BLOCK

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

PLAIN_TEXT = "Documento secreto"

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
        
def RSA_OAEP_encoder(plain, private_key):
    print('\n[RSA_OAEP] Encoding \'{}\' with private key ({}, {}) ...\n'.format(plain, hex(private_key[0]), hex(private_key[1])))

    enc = b''

    E = private_key[0]
    N = private_key[1]

    plain_blocks = []
    block = ''

    for char in plain:
        block += char
        if len(block) >= MAX_BLOCK_SIZE:
            plain_blocks.append(copy.deepcopy(block))
            block = ''

    if len(block) > 0:
        plain_blocks.append(copy.deepcopy(block))

    # print("blocks:", plain_blocks)

    sha256 = hashlib.sha256()
    r = numpy.random.randint(2, size=(20,))
    r = bytes(r.tolist())
    # print("r:", r, len(r))
    sha256.update(r)
    G = sha256.digest()
    # print("hashed_r:", G.hex())
        
    for block in plain_blocks:
        sha1 = hashlib.sha1()
        M = AddPadding(block)
        # print("M:", M)
        P1 = xor(M.encode(), G)
        sha1.update(P1)
        H = sha1.digest()
        P2 = xor(r, H)
        # print("G:", G.hex(), len(G))
        # print("H:", H.hex(), len(H))
        # print("P1:", P1.hex(), len(P1))
        # print("P2:", P2.hex(), len(P2))
        P = P1 + P2
        # print("P:", P.hex(), len(P))
    
        for b in P:
            enc_b = (b ** E) % N
            # print(hex(b), hex(enc_b))
            # print(enc_b.to_bytes(2, byteorder='big'))
            enc += enc_b.to_bytes(2, byteorder='big')

        sha1 = hashlib.sha1()
        
    return enc
    
def RSA_OAEP_decoder(encoded, public_key):
    print('\n[RSA_OAEP] Decoding \'{}\' with public key ({}, {}) ...\n'.format(encoded.hex(), hex(public_key[0]), hex(public_key[1])))

    dec = b''

    D = public_key[0]
    N = public_key[1]
    
    enc_blocks = []
    block = []

    for b in encoded:
        block.append(b)
        if len(block) >= OAEP_BPEB:
            enc_blocks.append(copy.deepcopy(block))
            block = []

    if len(block) > 0:
        enc_blocks.append(copy.deepcopy(block))

    # print("Encoded blocks:", enc_blocks)
        
    for block in enc_blocks:
        P = b''
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        for i in range(0, len(block), 2):
            # print(block[i], block[i+1])
            # print(block[i].to_bytes(1, byteorder='big'), block[i+1].to_bytes(1, byteorder='big'), block[i].to_bytes(1, byteorder='big') + block[i+1].to_bytes(1, byteorder='big'))
            b = block[i].to_bytes(1, byteorder='big') + block[i+1].to_bytes(1, byteorder='big')
            enc_b = (int.from_bytes(b, byteorder='big') ** D) % N
            # print(b.hex(), hex(enc_b))
            P += enc_b.to_bytes(1, byteorder='big')

        # print("P:", P.hex(), len(P))

        P1 = P[:OAEP_M_SIZE]
        P2 = P[OAEP_M_SIZE:]

        sha1.update(P1)
        H = sha1.digest()
        r = xor(P2, H)
        # print("r(?):", r)
        sha256.update(r)
        G = sha256.digest()

        # print("G:", G.hex(), len(G))
        # print("H:", H.hex(), len(H))
        # print("P1:", P1.hex(), len(P1))
        # print("P2:", P2.hex(), len(P2))

        M = xor(P1, G)
        dec += M.rstrip(b'\x00')
        
    return dec.decode()

def Chaves_assim():
    N, E, Pn = Get_N_and_E(MIN_BITSIZE)
    D = Get_D(E, Pn)

    public_key = (E, N)
    private_key = (D, N)
    
    print('N = {}'.format(hex(N)))
    print('E = {}'.format(hex(E)))
    print('D = {}'.format(hex(D)))
    
    return public_key, private_key

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

    for i in range(0, 4):
        word[i] = word[i] ^ curr_round[i]

def ExpandKey(key_state, round_count):
    new_key_state = numpy.zeros(shape=(4, 4), dtype=numpy.byte)

    w3 = copy.deepcopy(key_state[:,3]) # TODO
    # print('w3:\n{}'.format(w3))
    RotWord(w3)
    # print('w3(rotword):\n{}'.format(w3))
    SubWord(w3)
    # print('w3(subword):\n{}'.format(w3))
    AddRoundConst(w3, round_count)
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
            new_col = mat_mult(GALOIS_FIELD, col)
        else:
            new_col = mat_mult(INV_GALOIS_FIELD, col)

        for i in range(0, 4):
            curr_state[i][j] = new_col[i]
            
def AddRoundKey(curr_state, key_state):
    for j in range(0, 4):
        for i in range(0, 4):
            curr_state[i][j] = curr_state[i][j] ^ key_state[i][j]
    
def Compute_keys(key, rounds):
    keys = []
    round_count = 0

    key_state = numpy.zeros(shape=(4, 4), dtype='<u1')

    # fill key state with 16 byte key
    count = 0
    for j in range(0, 4):
        for i in range(0, 4):
            key_state[i][j] = key[count]
            count += 1

    # key_state[0] = [0x2b, 0x28, 0xab, 0x09]
    # key_state[1] = [0x7e, 0xae, 0xf7, 0xcf]
    # key_state[2] = [0x15, 0xd2, 0x15, 0x4f]
    # key_state[3] = [0x16, 0xa6, 0x88, 0x3c]

    keys.append(copy.deepcopy(key_state))

    for i in range(0, rounds):
        ExpandKey(key_state, round_count)
        keys.append(copy.deepcopy(key_state))
        round_count += 1

    return keys

def AES_encoder(plain, keys):
    encoded = b''
    state = numpy.zeros(shape=(4, 4), dtype='<u1')
    plain_offset = 0
    
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

        blocks = []
        round_count = 1

        key_state = keys[0]
          
        # Sequencia de operações
        AddRoundKey(state, key_state)
        
        for n in range(1, len(keys) - 1):
            SubBytes(state)
            ShiftRows(state)
            MixColumns(state)
            key_state = keys[round_count]
            AddRoundKey(state, key_state)
            round_count += 1
            
        SubBytes(state)
        ShiftRows(state)
        key_state = keys[round_count]
        AddRoundKey(state, key_state)
        
        encoded += state.transpose().tobytes()
                    
        state.fill(0)
        
    return encoded

def AES_decoder(encoded, keys):
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
        AddRoundKey(state, key_state)
        ShiftRows(state, inv=True)
        SubBytes(state, inv=True)
        
        for n in range(1, len(keys) - 1):
            key_state = keys[round_count]
            AddRoundKey(state, key_state)
            MixColumns(state, inv=True)
            ShiftRows(state, inv=True)
            SubBytes(state, inv=True)
            round_count -= 1
        
        key_state = keys[0]
        AddRoundKey(state, key_state)
          
        decoded += state.transpose().tobytes()
                    
        state.fill(0)
        
    return decoded.rstrip(b'\x00')

def HashFile(filename): # SHA3-256 (return HEX)
    sha3 = hashlib.sha256()
    hashed_file = ''

    try:
        with open(filename, 'rb') as f:
            while True:
                data = f.read(BUF_SIZE)
                if not data:
                    break
                sha3.update(data)
        
        hashed_file = sha3.hexdigest()
    except Exception as e:
        print(e)

    return hashed_file

class MyHTTPRequestHandler(BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def do_HEAD(self):
        self._set_headers()

    #handle GET command  
    def do_POST(self):

        length = int(self.headers.get('content-length'))
        request_body = json.loads(self.rfile.read(length))     

        filename = request_body['filename']

        print("Filename: {}\n".format(filename))
        file_hash = HashFile(filename)

        if len(file_hash) == 0:
            print("[X] Documento '{}' não encontrado !".format(filename))
            payload = {'error': 'Documento não encontrado'}

        else:
            print("File hash:", file_hash)

            # RSA cipher
            print("\n< RSA >")
            public_key, private_key = Chaves_assim()

            rsa_encoded = RSA_OAEP_encoder(file_hash, private_key)
            print("\n>>> RSA_encoded: {}".format(rsa_encoded.hex()))
            
            payload = {
                'doc': filename, # BYTE
                'encoded': rsa_encoded, # HEX
                'public_key': public_key # HEX
            }

        self._set_headers()
        self.wfile.write(json.dumps(payload).encode())

if __name__ == '__main__':
    numpy.set_printoptions(formatter={'int':hex})

    # SERVIDOR
    if argv[1] == 'server':
        print('http server is starting...')
        
        # LocalHost and Port
        server_address = ('127.0.0.1', 80)
        httpd = HTTPServer(server_address, MyHTTPRequestHandler)  
        print('http server is running...')  
        httpd.serve_forever()

    # CLIENTE
    elif argv[1] == 'client':
        connection = http.client.HTTPConnection('127.0.0.1', 80, timeout=10)
        print(connection)

        filename = input("> Arquivo para assinatura: ")

        headers = {
            'Content-type': 'application/json'
        }

        request_body = {
            'filename': filename
        }

        connection.request("POST", "/", json.dumps(request_body), headers)
        response = connection.getresponse()
        print("Status: {} and reason: {}".format(response.status, response.reason))
        
        payload = json.loads(response.read())

        print(payload)

        connection.close()

        input()

        if not payload['error']:
            print("PAYLOAD")
            print("Doc: {}".format(payload['doc']))
            print("Encoded hash: {}".format(payload['encoded'].hex()))
            print("Public key: ({}, {})".format(hex(payload['public_key'][0]), hex(payload['public_key'][1])))
            print()

            poss_hash = RSA_OAEP_decoder(payload['encoded'], payload['public_key'])
            hashed_doc = HashFile(payload['doc'])
            print("\n>>> RSA_decoded: {}".format(poss_hash))
            print("\n>>> Hashed doc: {}".format(hashed_doc))
            print()
            
            if poss_hash == hashed_doc:
                print("Documento é valido :)\n")
            else:
                print("Documento é invalido :(\n")

        # EAS cipher
        # print("\n< AES >")   
        # aes_key = Chave_sim(SIM_KEY_SIZE)
        # aes_key = 'satishcjisboring'
        # print("> key unicode:", aes_key.encode('utf-8'))

        # rounds = ROUNDS[len(aes_key) * 8]

        # aes_keys = Compute_keys(aes_key.encode('utf-8'), rounds)
        # aes_encoded = AES_encoder(plain_hash, aes_keys)
        # aes_decoded = AES_decoder(aes_encoded, aes_keys)

        # print("> AES_encoded:", aes_encoded)
        # print("> AES_decoded:", aes_decoded.decode('utf-8'))

        # # base64_bytes = base64.b64encode(rsa_encoded)
        # # print("> BASE64 encoded:", base64_bytes.decode('ascii'))

        # # from_base64 = base64.b64decode(base64_bytes)

        # # print("> BASE64 decoded:", from_base64)

    else:
        print("[X] Modo inválido (tente 'server' ou 'client')")