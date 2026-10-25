#!/usr/bin/env python3
"""Authorize exactly two REA P254 extract_firmware calls with existing owner key."""
import base64
import datetime
import hashlib
import json
import os
import pathlib
import secrets
import stat
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

EXPECTED_OWNER_PUB_DER_SHA256 = '99580a4806703661ca38f75a3cb95e47d46e32228cf89d5aa7ab55e95a4e25b4'
ACK = 'AUTORIZO_OPERACAO_SENSIVEL'
def canon(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode('ascii')

owner = pathlib.Path.home() / '.rea-owner'
private = owner / 'rea-owner-private.pem'
public = owner / 'rea-owner-public.pem'
for path in (owner, private, public):
    if not path.exists() or path.is_symlink():
        raise SystemExit('P254: chave de proprietario existente nao encontrada ou caminho inseguro; nenhuma chave nova sera criada')
for path in (private, public):
    if not path.is_file() or (stat.S_IMODE(path.stat().st_mode) & 0o077):
        raise SystemExit('P254: permissao insegura; parar sem alterar a chave')
public_key = serialization.load_pem_public_key(public.read_bytes())
der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
if hashlib.sha256(der).hexdigest() != EXPECTED_OWNER_PUB_DER_SHA256:
    raise SystemExit('P254: chave publica nao coincide com o proprietario original; parar')
private_key = serialization.load_pem_private_key(private.read_bytes(), password=None)
if not isinstance(private_key, Ed25519PrivateKey) or private_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != der:
    raise SystemExit('P254: a chave privada nao corresponde a publica; parar')

nonce = secrets.token_hex(16)
expires_at = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=12)).strftime('%Y-%m-%dT%H:%M:%SZ')
args = {
    'path': '/opt/rea-reversa/rea/_reference/rea-p253-controlled-firmware/firmware.bin',
    'output_directory': '/var/lib/rea-reversa/rea-p254-firmware-' + nonce[:12],
    'max_depth': 3,
}
sha = hashlib.sha256(canon(args)).hexdigest()
reason1 = ('P254: extrair apenas a amostra publica GZIP/TAR de 395 bytes para uma pasta nova e especifica na StateDirectory /var/lib/rea-reversa, com autorizacao precisa na ponte, sem reiniciar o REA e sem abrir ou fechar binarios.')
reason2 = ('P254: repetir a mesma extracao na mesma pasta apenas para confirmar recusa de sobrescrita, sem apagar ficheiros antigos nem alterar Evidence anteriores.')
assert all(12 <= len(reason) <= 400 for reason in (reason1, reason2))

print('\nREA P254 - PEDIDO DE APROVACAO EXATA (DUAS CHAMADAS DA MESMA FERRAMENTA)')
print('Ferramenta: extract_firmware | operacao sensivel - NAO SERÁ EXECUTADA NESTE ANDROID')
print('Origem: amostra publica de 395 bytes gerada e verificada na VPS, SHA-256 fdee9c184dc1251981c5c82ef82091c03106a62a5e258c536ef3ef650a9c7ebf')
print('Destino exato:', args['output_directory'])
print('Escopo: so este diretorio na StateDirectory existente. Sem desbloqueio global ou reinicio do REA.')
print('Chamada 1: extracao controlada. Chamada 2: repetir e confirmar recusa de sobrescrita.')
print('Pedido: leitura previa, duas chamadas assinadas; consultas finais poderao nao correr se a segunda recusar a sobrescrita.')
print('Depois da operacao sera feita uma consulta separada de Evidence. Nenhuma chave PEM e enviada.')
print('SHA-256 dos argumentos:', sha)
print('Validade ate (UTC):', expires_at)
print('As assinaturas sao criadas LOCALMENTE. Nao envia a chave privada a lado nenhum.')
if input('Escreve '+ACK+' apenas se concordares com estas DUAS chamadas: ').strip() != ACK:
    raise SystemExit('P254 NAO AUTORIZADA - nao foi criado pedido')

def signed_step(index, reason):
    payload = {
        'purpose': 'REA_OWNER_APPROVAL_V1',
        'nonce': nonce, 'expires_at': expires_at, 'step_index': index,
        'tool': 'extract_firmware', 'arguments_sha256': sha,
        'scope': 'sensitive', 'reason': reason, 'acknowledgement': ACK,
    }
    signature = private_key.sign(canon(payload))
    public_key.verify(signature, canon(payload))
    return {
        'tool': 'extract_firmware', 'arguments': dict(args),
        'authorization': {
            'tool': 'extract_firmware', 'arguments_sha256': sha,
            'scope': 'sensitive', 'reason': reason,
            'confirmed_by_owner': True, 'acknowledgement': ACK,
            'owner_signature': base64.b64encode(signature).decode('ascii'),
        },
    }

body = {'protocol': 1, 'nonce': nonce, 'expires_at': expires_at,
    'steps': [
        {'tool': 'get_evidence_bundle', 'arguments': {'detail': 'complete'}},
        signed_step(1, reason1),
        signed_step(2, reason2),
        {'tool': 'get_evidence_bundle', 'arguments': {'detail': 'complete'}},
        {'tool': 'list_unknowns', 'arguments': {}},
    ]}
os.umask(0o077)
output = pathlib.Path.home() / ('rea-p254-signed-' + nonce[:8] + '.json')
with output.open('x', encoding='ascii') as file:
    file.write(canon(body).decode('ascii')+'\n')
print('\nREA_P254_OWNER_SIGNATURE=PASS_LOCAL_ONLY')
print('FICHEIRO_TERMINAL='+str(output))
print('CHAVE_PRIVADA=PERMANECE_NO_ANDROID')
route = '/download/'+secrets.token_hex(16)
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != route:
            self.send_error(404)
            return
        raw = output.read_bytes()
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Disposition','attachment; filename="'+output.name+'"')
        self.send_header('Content-Length',str(len(raw)))
        self.send_header('Cache-Control','no-store')
        self.end_headers()
        self.wfile.write(raw)
    def log_message(self, fmt, *arguments):
        pass

server = HTTPServer(('127.0.0.1',0), Handler)
print('ABRE_NO_CHROME=http://127.0.0.1:'+str(server.server_port)+route, flush=True)
print('Descarrega o JSON pelo Chrome e anexa-o nesta conversa. NAO envies as chaves PEM.', flush=True)
server.handle_request()
server.server_close()
print('P254_JSON_DOWNLOAD_LOCAL=PASS')
