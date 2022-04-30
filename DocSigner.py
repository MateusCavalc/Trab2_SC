from MyCrypt import *
from sys import argv
from http.server import BaseHTTPRequestHandler, HTTPServer
import http.client
import json

FROM_RAW = 1
FROM_FILE = 2

def SignDoc(filename):
    payload = {}
    print(" [*] Gerando hash do arquivo '{}' ...".format(filename))
    file_hash = RSA_OAEP.DoHash(filename, fromFile=True)


    if len(file_hash) == 0:
        print("\n [X] Documento '{}' não encontrado !".format(filename))
        payload = {'error': 'Documento não encontrado'}

    else:
        print(" File hash:", file_hash)

        # RSA cipher
        print("\n< RSA >")
        print(" [*] Gerando chaves RSA ...")
        public_key, private_key = RSA_OAEP.Generate_Key_Pair(MIN_BITSIZE)
        payload['public_key'] = public_key # INT

        print("\n [*] Codificando Hash do arquivo ...")
        rsa_encoded = RSA_OAEP.RSA_OAEP_encoder(file_hash.encode(), private_key) # BASE64
        # print(">>> Signed Doc (BASE64): {}".format(rsa_encoded))
        payload['dig_sig'] = rsa_encoded # BASE64

        # AES cipher
        print("\n< AES CTR (Counter) >")
        print(" [*] Gerando chave AES e nonce ...")
        aes_key = AES.Generate_Key(SIM_KEY_SIZE)
        nonce = random.getrandbits(64)
        print(" > key:", aes_key)
        print(" > Random generated Nonce: {:064b}\n".format(nonce))

        try:
            print(" [*] Codificando arquivo ...")
            aes_ctr = AES_CTR()
            aes_ctr.ComputeKeyBlocks(aes_key)
            aes_ctr.SetNonce(nonce.to_bytes(8, byteorder='big'))

            encoded = aes_ctr.Encode(filename=filename)
            # print("> AES CTR encoded file (HEX):", encoded.hex())
            payload['doc'] = encoded.hex() # HEX

            print(" [*] Codificando chave AES e nonce usando RSA ...")
            aes_key_encoded = RSA_OAEP.RSA_OAEP_encoder(aes_key.encode(), private_key)
            nonce_encoded = RSA_OAEP.RSA_OAEP_encoder(nonce.to_bytes(8, byteorder='big'), private_key)
            # print("> AES CTR encoded key (BASE64):", (aes_key_encoded, nonce_encoded))
            payload['aes_key'] = (aes_key_encoded, nonce_encoded) # BASE64
        except NoKeyBlocks:
            print("\n [X] Os blocos de chaves não foram computados.\n")
        except NoNonce:
            print("\n [X] Nonce não definido.\n")

    return payload

def SignMsg(plain):
    payload = {}
    print("\n > Plain:", plain)
    print(" [*] Gerando hash da mensagem ...")
    plain_hash = RSA_OAEP.DoHash(plain.encode())
    # RSA cipher
    print("\n< RSA >")
    print(" [*] Gerando chaves RSA ...")
    public_key, private_key = RSA_OAEP.Generate_Key_Pair(MIN_BITSIZE)
    payload['public_key'] = public_key # INT

    print("\n [*] Codificando Hash da mensagem ...")
    rsa_encoded = RSA_OAEP.RSA_OAEP_encoder(plain_hash.encode(), private_key) # BASE64
    # print(">>> Signed Doc (BASE64): {}".format(rsa_encoded))
    payload['dig_sig'] = rsa_encoded # BASE64

    print("\n< AES CTR (Counter) >")
    aes_key = AES.Generate_Key(SIM_KEY_SIZE)
    nonce = random.getrandbits(64)
    print("> key:", aes_key)
    print("> Random generated Nonce: {:064b}\n".format(nonce))

    try:
        print(" [*] Codificando mensagem ...")
        aes_ctr = AES_CTR()
        aes_ctr.ComputeKeyBlocks(aes_key)
        aes_ctr.SetNonce(nonce.to_bytes(8, byteorder='big'))

        encoded = aes_ctr.Encode(plain=plain)
        # print("> AES CTR encoded file (HEX):", encoded.hex())
        payload['doc'] = encoded.hex() # HEX

        print(" [*] Codificando chave AES e nonce usando RSA ...")
        aes_key_encoded = RSA_OAEP.RSA_OAEP_encoder(aes_key.encode(), private_key)
        nonce_encoded = RSA_OAEP.RSA_OAEP_encoder(nonce.to_bytes(8, byteorder='big'), private_key)
        # print("> AES CTR encoded key (BASE64):", (aes_key_encoded, nonce_encoded))
        payload['aes_key'] = (aes_key_encoded, nonce_encoded) # BASE64
    except NoKeyBlocks:
        print("\n [X] Os blocos de chaves não foram computados.\n")
    except NoNonce:
        print("\n [X] Nonce não definido.\n")
    
    return payload

def Server():
    print('http server is starting...')
    server_address = ('127.0.0.1', 80)
    httpd = HTTPServer(server_address, MyHTTPRequestHandler)  
    print('http server is running...')
    httpd.serve_forever()

def Client(mode):
    connection = http.client.HTTPConnection('127.0.0.1', 80, timeout=60)

    headers = {'Content-type': 'application/json'}
    request_body = {'mode': mode}
    
    if mode == FROM_FILE:
        filename = input("> Arquivo para assinatura: ")
        request_body['filename'] = filename

    connection.request("POST", "/", json.dumps(request_body), headers)

    print(' [...] Aguardando documento ...')
    
    payload = json.loads(connection.getresponse().read())

    connection.close()

    if 'error' not in payload:
        print("\n------------------------------------------------------------")
        print("PAYLOAD")
        print("Encoded Doc length: {} bytes".format(len(payload['doc'])))
        print("Encoded AES key (BASE64): {}".format(payload['aes_key']))
        print("Digital signature (BASE64): {}".format(payload['dig_sig']))
        print("Public key (HEX): ({}, {})".format(hex(payload['public_key'][0]), hex(payload['public_key'][1])))
        print("------------------------------------------------------------")

        payload_enc_doc = bytes.fromhex(payload['doc'])
        payload_enc_aes_key = payload['aes_key'][0]
        payload_enc_nonce = payload['aes_key'][1]
        payload_enc_base64 = payload['dig_sig']
        payload_pkey = (int(payload['public_key'][0]), int(payload['public_key'][1]))

        print("\n< RSA >")
        print(" [*] Decodificando hash recebido e chave AES ...")
        target_hash = RSA_OAEP.RSA_OAEP_decoder(payload_enc_base64, payload_pkey).decode()
        aes_key = RSA_OAEP.RSA_OAEP_decoder(payload_enc_aes_key, payload_pkey).decode()
        nonce_bytes = RSA_OAEP.RSA_OAEP_decoder(payload_enc_nonce, payload_pkey)

        print("\n< AES CTR (Counter) >")
        print(" [*] Decodificando documento recebido ...")
        aes_ctr = AES_CTR()
        aes_ctr.ComputeKeyBlocks(aes_key)
        aes_ctr.SetNonce(nonce_bytes)
        doc = aes_ctr.Decode(payload_enc_doc)

        print(" [*] Calculando hash documento recebido ...")
        doc_hash = RSA_OAEP.DoHash(doc)
        print(" [*] Comparando hashes ...")
        print("\n>>> Desired doc  (hash): {}".format(target_hash))
        print(">>> Received doc (hash): {}\n".format(doc_hash))

        if target_hash == doc_hash:
            if mode == FROM_FILE:
                print(" [#] Documento é válido :)")
                with open('./client_docs/' + filename, 'wb') as f:
                    data = f.write(doc)
            else:
                print(" [#] Mensagem é válida :)")
                print("\n [#] Mensagem: {}".format(doc.decode()))
        else:
            if mode == FROM_FILE:   print(" [X] Documento é inválido :(")
            else: print(" [#] Mensagem inválida :(")
    
    else:
        print(" [!] Não foi possível encontrar o documento '{}'".format(filename))

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

        if request_body['mode'] == FROM_FILE:
            filename = request_body['filename']
            print("Filename: {} \n".format(filename))
            payload = SignDoc(filename)    
        else:
            plain = input("> Enter string message to sign: ")
            payload = SignMsg(plain)

        print("\n [$] Assinatura completa, enviando para o cliente\n")

        self._set_headers()
        self.wfile.write(json.dumps(payload).encode())

if __name__ == '__main__':
    
    if len(argv) > 1:
        if argv[1] == 'server':
            Server() # SERVIDOR
        
        elif argv[1] == 'client':
            if argv[2] == '--file':
                Client(FROM_FILE)
            elif argv[2] == '--raw':
                Client(FROM_RAW)
            else:
                print("[X] Modo de assinatura inválida (tente '--file' ou '--raw')")

        else:
            print("[X] Modo inválido (tente 'server' ou 'client')")
    
    else:
        print("[X] Nenhum modo especificado (tente 'server' ou 'client')")