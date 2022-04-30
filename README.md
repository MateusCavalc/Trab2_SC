
# Segurança Computacional - Trabalho 2

Este trabalho simula um sistema de assinatura digital de mensagens simples (entradas de texto) e arquivos baseado em uma arquitetura de cliente/servidor.
## [Servidor]

De maneira inicial, é necessário executar o arquivo 'DocSigner.py' como servidor. Para isso, basta executar a seguinte linha de comando:

```bash
  python DocSigner.py server
```

A partir disso, será hospedado um servidor REST no endereço 127.0.0.1 e porta 80 que responde às requisições do cliente.

![App Screenshot](https://github.com/MateusCavalc/Trab2_SC/blob/main/rel/server_exemplo.png)

## [Cliente]
### > Assinatura de arquivo

Com o servidor rodando em outro terminal, é necessário executar o lado do cliente. Para enviar uma requisição de assinatura de arquivo, basta executar a seguinte linha de comando:

```bash
  python DocSigner.py client --file
```

Logo após a execução do comando, o lado do cliente pede (input de usuário) o nome do arquivo desejado para assinatura. Caso exista no lado do servidor (os arquivos são procurado no diretório ./server_docs/), ele recebe o documento assinado e verifica sua integridade. Caso documento seja válido, ele é salvo no diretório ./client_docs/

### Exemplo

![App Screenshot](https://github.com/MateusCavalc/Trab2_SC/blob/main/rel/modo2_client.png)
![App Screenshot](https://github.com/MateusCavalc/Trab2_SC/blob/main/rel/modo2_server.png)

### > Assinatura de mensagem
Para enviar uma requisição de assinatura de mensagem (entrada de texto), basta executar a seguinte linha de comando:

```bash
  python DocSigner.py client --raw
```

Logo após a execução do comando, o lado do servidor pede (input de usuário) uma mensagem para assinar e enviarao cliente. Ao efetuar a assinatura da mensagem, os dados da assinatura são enviado ao cliente, que valida a mensagem recebida.

### Exemplo

![App Screenshot](https://github.com/MateusCavalc/Trab2_SC/blob/main/rel/modo1_client.png)
![App Screenshot](https://github.com/MateusCavalc/Trab2_SC/blob/main/rel/modo1_server.png)

## Observações

- A assinatura de arquivos grandes (arquivos .pdf, por exemplo) pode causar timeout no lado do cliente, uma vez que a implementação do algoritmo de criptografia AES CTR foi feita de maneira sequencial.


## Autores

- [@EuMesmo](https://github.com/MateusCavalc)
- [@MarianaMendanha](https://github.com/MarianaMendanha)
