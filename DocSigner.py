from MyCrypt import *
from sys import argv
from http.server import BaseHTTPRequestHandler, HTTPServer
import http.client
import json

FROM_RAW = 1
FROM_FILE = 2

KEY_PAIR_FILENAME = 'KeyPair.kp'

class MyHTTPRequestHandler(BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def do_HEAD(self):
        self._set_headers()

    #handle POST command  
    def do_POST(self):
        length = int(self.headers.get('content-length'))
        request_body = json.loads(self.rfile.read(length)) 

        # Recebe o payload do cliente com o modo de assinatura
        # FROM_FILE = Assina arquivo do diretório ./server_docs
        # FROM_RAW = Assina mensagem enviada pelo servidor

        mode = request_body['mode']

        if mode == FROM_FILE:
            # recebe nome do arquivo para assinar
            toSign = request_body['filename']
        else:
            # Entra mensagem para assinar
            toSign = input("\n[?] Enter string message to sign: ")

        # Assina o conteudo de 'toSign' de acordo com o modo
        payload = Sign(toSign, mode)

        print("\n\n [$] Assinatura completa, enviando para o cliente\n")

        # Envia informações da assinatura para o cliente
        self._set_headers()
        self.wfile.write(json.dumps(payload).encode())

# Método de inicialização de servidor
def Server():
    print('http server is starting...')
    server_address = ('127.0.0.1', 80)
    httpd = HTTPServer(server_address, MyHTTPRequestHandler)  
    print('http server is running...')
    httpd.serve_forever()

# Método de inicialização de cliente
def Client(mode):
    connection = http.client.HTTPConnection('127.0.0.1', 80, timeout=None)

    # Monta o header e corpo de requisição
    headers = {'Content-type': 'application/json'}
    request_body = {'mode': mode}
    
    if mode == FROM_FILE:
        filename = input("\n [?] Arquivo para assinatura: ")
        request_body['filename'] = filename

    # Envia requisição de arquivo/mensagem ao servidor
    connection.request("POST", "/", json.dumps(request_body), headers)

    print('\n [...] Aguardando documento ...')
    
    # Payload recebido do servidor com as informações sobre a assinatura
    payload = json.loads(connection.getresponse().read())

    connection.close()

    if 'error' not in payload:
        print("\n------------------------------------------------------------")
        print("PAYLOAD")
        print("Encoded Doc length: {} bytes".format(len(payload['doc'])))
        print("Encoded AES key (BASE64): {}".format(payload['aes_key']))
        print("Digital signature (BASE64): {}".format(payload['dig_sig']))
        print("------------------------------------------------------------")

        # Documento encriptado (AES CTR)
        payload_enc_doc = bytes.fromhex(payload['doc'])
        # Chave AES encriptada (BASE64)
        payload_enc_aes_key = payload['aes_key'][0]
        # Nonce encriptado
        payload_enc_nonce = payload['aes_key'][1]
        # Assinatura digital (BASE64)
        payload_enc_base64 = payload['dig_sig']

        print("\n [!] Verificando assinatura ...")

        # Pega a chave pública (RSA) do arquivo ./KeyPair.kp
        public_key = RSA_OAEP.GetPublicKeyFromFile(KEY_PAIR_FILENAME)
        print(" [*] Decodificando hash recebido e chave AES ...")
        # Decodifica o hash recebido, a chave AES e o nonce ((utilizando RSA OAEP))
        target_hash = RSA_OAEP.RSA_OAEP_decoder(payload_enc_base64, public_key).decode()
        aes_key = RSA_OAEP.RSA_OAEP_decoder(payload_enc_aes_key, public_key).decode()
        nonce_bytes = RSA_OAEP.RSA_OAEP_decoder(payload_enc_nonce, public_key)
        print("  |-[$] Hash (recebido):", target_hash)
        print("  |-[$] Key:", aes_key)
        print("  |-[$] Nonce: {:064b}".format(int.from_bytes(nonce_bytes, byteorder="big")))
        # Monta a estrutura para o algoritmo AES
        aes_ctr = AES_CTR()
        aes_ctr.ComputeKeyBlocks(aes_key)
        aes_ctr.SetNonce(nonce_bytes)
        # Decodifica o documento recebido (AES CTR)
        print(" [*] Decodificando documento recebido usando AES CTR ...")
        doc = aes_ctr.Decode(payload_enc_doc)

        print()
        # Calcula o hash do documento decifrado e compara com o hsh recebido
        doc_hash = RSA_OAEP.DoHash(doc)
        print("  |-[$] Hash (calculado):", target_hash)
        print(" [*] Comparando hashes ...")
        print("\n>>> Esperado (hash): {}".format(target_hash))
        print(">>> Recebido (hash): {}\n".format(doc_hash))

        if target_hash == doc_hash:
            # Se o documento for válido, salva no diretório ./client_docs
            if mode == FROM_FILE:
                print(" [$] Documento é válido :)\n")
                with open('./client_docs/' + filename, 'wb') as f:
                    data = f.write(doc)
                os.system("start ./client_docs/" + filename)
            # Se mensagem for válida, mostra no terminal
            else:
                print(" [$] Mensagem é válida :)\n")
                print(" [$] Mensagem: {}\n".format(doc.decode()))
        else:
            if mode == FROM_FILE:
                print(" [X] Documento é inválido :(\n")
            else: print(" [X] Mensagem inválida :(\n")
    
    else:
        print(" [!] Não foi possível encontrar o documento '{}'".format(filename))

# Método de assinatura de conteudo (arquivo ou mensagem) - Retorna payload (json) para enviar ao cliente 
def Sign(toSign, mode):
    payload = {}

    # Gera hash do conteudo de acordo com o modo (SHA3-256)
    if mode == FROM_FILE:
        print("\n > Filename: {}".format(toSign))
        hashed = RSA_OAEP.DoHash(toSign, fromFile=True)
    else:
        print("\n > Plain: {}".format(toSign))
        hashed = RSA_OAEP.DoHash(toSign.encode())

    # Se não foi possível encontrar o arquivo, retorna string nula para o hash
    if len(hashed) == 0:
        print("\n [X] Documento '{}' não encontrado !".format(filename))
        payload = {'error': 'Documento não encontrado'}

    else:
        print("  |> Hash: {}".format(hashed))

        # Pega a chave privada (RSA) do arquivo ./KeyPair.kp
        private_key = RSA_OAEP.GetPrivateKeyFromFile(KEY_PAIR_FILENAME)

        # Codifica o hash do conteudo e coloca no payload
        print("  [*] Codificando Hash usando RSA OAEP ...")
        rsa_encoded = RSA_OAEP.RSA_OAEP_encoder(hashed.encode(), private_key) # BASE64
        print("   |> Assinatura (BASE64): {}".format(rsa_encoded))
        payload['dig_sig'] = rsa_encoded # BASE64

        print(" [*] Gerando chave AES e nonce ...")
        # Gera a chave AES e o Nonce
        aes_key = AES.Generate_Key(SIM_KEY_SIZE)
        nonce = random.getrandbits(64)
        print("  |-[$] Key:", aes_key)
        print("  |-[$] Random generated Nonce: {:064b}".format(nonce))

        # Codifica a chave aes e nonce (utilizando RSA OAEP) e coloca no payload
        print("     |> Codificando chave AES e nonce usando RSA ...")
        aes_key_encoded = RSA_OAEP.RSA_OAEP_encoder(aes_key.encode(), private_key)
        nonce_encoded = RSA_OAEP.RSA_OAEP_encoder(nonce.to_bytes(8, byteorder='big'), private_key)
        payload['aes_key'] = (aes_key_encoded, nonce_encoded) # BASE64

        try:
            # Monta a estrutura para o algoritmo AES
            aes_ctr = AES_CTR()
            aes_ctr.ComputeKeyBlocks(aes_key)
            aes_ctr.SetNonce(nonce.to_bytes(8, byteorder='big'))
            # Codifica o documento (AES CTR) e coloca no payload
            if mode == FROM_FILE:
                print(" [*] Codificando arquivo usando AES CTR ...")
                encoded = aes_ctr.Encode(filename=toSign)
            else:
                print(" [*] Codificando mensagem usando AES CTR ...")
                encoded = aes_ctr.Encode(plain=toSign)
            payload['doc'] = encoded.hex() # HEX
        except NoKeyBlocks:
            print("\n [X] Os blocos de chaves não foram computados.\n")
        except NoNonce:
            print("\n [X] Nonce não definido.\n")

    return payload

def main():
    if len(argv) > 1:
        # Modo de geração de arquivo com chaves pública e privada
        if argv[1] == 'genkeys':
            if not os.path.exists('./' + KEY_PAIR_FILENAME):
                RSA_OAEP.Generate_Key_Pair(KEY_PAIR_FILENAME, MIN_BITSIZE)
            else:
                if input(" [!] Já existe um par de chaves RSA criadas, gostaria de sobrescrever as chaves existentes? (y/n): ") == 'y':
                    RSA_OAEP.Generate_Key_Pair(KEY_PAIR_FILENAME, MIN_BITSIZE)
        else:
            # Verifica se o arquivo com as chaves RSA existem
            if not os.path.exists('./' + KEY_PAIR_FILENAME):
                print("[X] Não foi possível encontrar o arquivo '{}'. Para gerar o par de chaves (RSA), tente executar o script com o modo 'genkeys'.\n".format(KEY_PAIR_FILENAME))
            else:
                # Modo SERVIDOR
                if argv[1] == 'server':
                    Server() # SERVIDOR
                
                # Modo CLIENTE
                elif argv[1] == 'client':
                    if len(argv) == 3:
                        if argv[2] == '--file':
                            Client(FROM_FILE)
                        elif argv[2] == '--raw':
                            Client(FROM_RAW)
                        else:
                            print("[X] Flag de cliente inválida (tente '--file' ou '--raw')")
                    else:
                        print("[X] Flag de cliente não fornecida (tente '--file' ou '--raw')")

                else:
                    print("[X] Modo inválido (tente 'genkeys', 'server' ou 'client')")
    
    else:
        print("[X] Nenhum modo especificado (tente 'genkeys', 'server' ou 'client')")

if __name__ == '__main__':
    main()