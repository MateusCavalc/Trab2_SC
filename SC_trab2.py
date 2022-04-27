from MyCrypt import *
from sys import argv
from http.server import BaseHTTPRequestHandler, HTTPServer
import http.client
import json

def Server():
    print('http server is starting...')
    server_address = ('127.0.0.1', 80)
    httpd = HTTPServer(server_address, MyHTTPRequestHandler)  
    print('http server is running...')
    httpd.serve_forever()

def Client():
    connection = http.client.HTTPConnection('127.0.0.1', 80, timeout=60)

    filename = input("> Arquivo para assinatura: ")

    headers = {
        'Content-type': 'application/json'
    }
    request_body = {
        'filename': filename
    }

    connection.request("POST", "/", json.dumps(request_body), headers)

    print(' [...] Aguardando documento ...')
    
    payload = json.loads(connection.getresponse().read())

    connection.close()

    if 'error' not in payload:
        print("\n------------------------------------------------------------")
        print("PAYLOAD")
        print("Doc length: {} bytes".format(len(payload['doc'])))
        print("Digital signature (BASE64): {}".format(payload['dig_sig']))
        print("Public key: ({}, {})".format(hex(payload['public_key'][0]), hex(payload['public_key'][1])))
        print("------------------------------------------------------------")

        payload_doc = bytes.fromhex(payload['doc'])
        payload_encoded_base64 = payload['dig_sig']
        payload_pkey = (int(payload['public_key'][0]), int(payload['public_key'][1]))

        target_hash = RSA_OAEP.RSA_OAEP_decoder(payload_encoded_base64, payload_pkey)
        _, doc_hash = RSA_OAEP.DoHash(payload_doc)
        print("\n>>> Desired doc  (hash): {}".format(target_hash))
        print(">>> Received doc (hash): {}\n".format(doc_hash))
        
        if target_hash == doc_hash:
            print(" [#] Documento é valido :)")
            with open('E:/Users/droto/Desktop/Trab2_SC/docs_validos/' + filename.split("/", 1)[1], 'wb') as f:
                data = f.write(payload_doc)
        else:
            print(" [X] Documento é invalido :(")
    
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

        filename = request_body['filename']

        print("Filename: {} ({})\n".format(filename, type(filename)))

        file_bytes, file_hash = RSA_OAEP.DoHash(filename, fromFile=True)

        if len(file_hash) == 0:
            print("[X] Documento '{}' não encontrado !".format(filename))
            payload = {'error': 'Documento não encontrado'}

        else:
            print("File hash:", file_hash)

            # RSA cipher
            print("\n< RSA >")
            public_key, private_key = RSA_OAEP.Generate_Key_Pair(MIN_BITSIZE)

            rsa_encoded = RSA_OAEP.RSA_OAEP_encoder(file_hash, private_key) # BASE64
            print(">>> Digital Signature (BASE64): {}\n".format(rsa_encoded))
            
            payload = {
                'doc': file_bytes.hex(), # HEX
                'dig_sig': rsa_encoded, # BASE64
                'public_key': public_key # HEX
            }

        self._set_headers()
        self.wfile.write(json.dumps(payload).encode())

if __name__ == '__main__':
    
    if argv[1] == 'server':
        Server() # SERVIDOR
    
    elif argv[1] == 'client':
        Client() # CLIENTE

    elif argv[1] == 'aes':
        # EAS cipher
        print("\n< AES CTR (Counter) >")
        plain = input("> Enter string message to encrypt: ")
        aes_key = AES.Generate_Key(SIM_KEY_SIZE)
        nonce = random.getrandbits(64)
        print("\n> Plain:", plain)
        print("> key:", aes_key)
        print("> Random generated Nonce: {:064b}\n".format(nonce))

        try:
            aes_ctr = AES_CTR()
            aes_ctr.ComputeKeyBlocks(aes_key)
            aes_ctr.SetNonce(nonce.to_bytes(8, byteorder='big'))

            encoded = aes_ctr.Encode(plain)
            print("> AES CTR encoded (HEX):", encoded.hex(':'))
            
            decoded = aes_ctr.Decode(encoded)
            print("> AES CTR decoded:", decoded)
        except NoKeyBlocks:
            print("\n [X] Os blocos de chaves não foram computados.\n")
        except NoNonce:
            print("\n [X] Nonce não definido.\n")

    else:
        print("[X] Modo inválido (tente 'server' ou 'client')")