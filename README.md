
# Segurança Computacional - Trabalho 2

Este trabalho simula um sistema de assinatura digital de mensagens simples (entradas de texto) e arquivos baseado em uma arquitetura de cliente/servidor.
## Servidor

De maneira inicial, é necessário executar o arquivo 'SC_trab2.py' como servidor. Para isso, basta executar a seguinte linha de comando:

```bash
  python SC_trab2.py server
```

A partir disso, será hospedado um servidor REST no endereço 127.0.0.1 e porta 80 que responde às requisições do cliente.

## Cliente
### Assinatura de arquivo

Com o servidor rodando em outro terminal, é necessário executar o lado do cliente. Para enviar uma requisição de assinatura de arquivo, basta executar a seguinte linha de comando:

```bash
  python SC_trab2.py client --file
```

Logo após a execução do comando, o lado do cliente pede (input de usuário) o nome do arquivo desejado para assinatura. Caso exista no lado do servidor, ele recebe o documento assinado e verifica sua integridade.

### Assinatura de mensagem
Para enviar uma requisição de assinatura de mensagem (entrada de texto), basta executar a seguinte linha de comando:

```bash
  python SC_trab2.py client --raw
```

Logo após a execução do comando, o lado do servidor pede (input de usuário) uma mensagem para assinar e enviarao cliente. Ao efetuar a assinatura da mensagem, os dados da assinatura são enviado ao cliente, que valida a mensagem recebida.
## Observações

- A assinatura de arquivos grandes (arquivos .pdf, por exemplo) pode causar timeout no lado do cliente, uma vez que a implementação do algoritmo de criptografia AES CTR foi feita de maneira sequencial.

