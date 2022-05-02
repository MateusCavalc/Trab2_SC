from MyCrypt import *
from sys import argv

def main():
    k = 9
    print(u' \u2581'*k)
    print(u'\u2595' + " Codificação AES " + u'\u258F')
    print(u' \u2594'*k)

    plain = input(' [?] Mensagem para codificação: ')
    chave = input(' [?] Chave (16 caracteres)\n  |> (Enter para gerar chave aleatória): ')
    while len(chave) > 0 and len(chave) < 16:
        chave = input(' [!] Chave deve ter tamanho 16!\n  |> (Enter para gerar chave aleatória): ')
    
    if(len(chave) == 0):
        chave = AES.Generate_Key(SIM_KEY_SIZE)
    
    print('\n [*] Iniciando codificação AES (CTR MODE)')
    print('  |-[$] Mensagem:', plain)
    print('  |-[$] Chave:   ', chave)
    print(' [*] Gerando Nonce aleatório ...')
    nonce = random.getrandbits(64)
    print('  |-[$] Nonce:   {:064b}'.format(nonce))
    print('  |')
    print(' [*] Codificando \'{}\' ...'.format(plain))
    aes_ctr = AES_CTR()
    aes_ctr.ComputeKeyBlocks(chave)
    aes_ctr.SetNonce(nonce.to_bytes(8, byteorder='big'))
    encoded = base64.b64encode(aes_ctr.Encode(plain=plain)).decode()
    print('\n  |')

    print(' [$] Mensagem codificada: ', encoded)
    print('  |')
    print(' [*] Decodificando \'{}\' ...'.format(encoded))
    orig = aes_ctr.Decode(base64.b64decode(encoded.encode()))
    print('\n  |')
    print(' [$] Mensagem original: {}\n'.format(orig.decode()))

if __name__ == '__main__':
    main()