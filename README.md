# Remote Command Execution Server

Este é um servidor HTTP em Python que permite a execução remota de comandos em um sistema alvo. Ele oferece suporte a comunicações HTTP e HTTPS.

## Descrição

O servidor foi desenvolvido em Python 3 e permite que um sistema cliente envie comandos para execução no servidor remoto. Ele suporta a execução de comandos PowerShell em sistemas Windows.

## Funcionalidades Principais

- Aceita conexões HTTP e HTTPS.
- Execução remota de comandos PowerShell.
- Geração automática de payloads para estabelecer uma conexão reversa com o servidor.

## Requisitos

- Python 3.x instalado.
- Acesso a um sistema operacional compatível com Python (Windows, Linux, macOS).
- Certificado SSL válido (para conexões HTTPS).

## Como Usar

1. Clone o repositório.
2. Instale os requisitos executando `pip install -r requirements.txt`.
3. Execute o servidor usando o comando `python3 server.py`.
4. Use um cliente HTTP ou HTTPS para enviar comandos para execução.

## Exemplos de Uso

- Execução remota de comandos: `curl -X POST -d "command=whoami" http://localhost:8080`.
- Execução remota de scripts: `curl -X POST -F "script=@script.ps1" http://localhost:8080`.
- Restaurar sessão ao vivo (se ativado): `curl -X GET http://localhost:8080`.

## Notas

- Este servidor é destinado apenas para fins educacionais e de teste. Use com responsabilidade.
- A execução remota de comandos pode representar um risco de segurança, especialmente em sistemas não autenticados.
