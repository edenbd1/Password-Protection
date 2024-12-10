from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
import base64
import tink
from tink import daead, core
import signal
import sys
import warnings

# Désactiver les warnings de dépréciation
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Initialisation de Tink
daead.register()

# Création de la clé de manière plus moderne
key_template = daead.deterministic_aead_key_templates.AES256_SIV
keyset_handle = tink.new_keyset_handle(key_template)
CRYPTO = keyset_handle.primitive(daead.DeterministicAead)

class EncryptionHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            # Lecture des données
            length = int(self.headers.get('content-length', 0))
            data = parse_qs(self.rfile.read(length).decode())
            
            if 'hashed_password' not in data or 'login' not in data:
                self.send_error(400, "Données manquantes")
                return

            # Encryption
            password_data = base64.b64decode(data['hashed_password'][0])
            associated_data = f"{self.client_address[0]}:{data['login'][0]}".encode()
            
            encrypted = CRYPTO.encrypt_deterministically(password_data, associated_data)
            
            # Réponse
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(base64.b64encode(encrypted))

        except Exception as e:
            print(f"Erreur: {str(e)}")
            self.send_error(500, "Erreur serveur")

    def log_message(self, format, *args):
        # Désactiver les logs HTTP par défaut
        pass

def signal_handler(signum, frame):
    print('\nArrêt du serveur...')
    sys.exit(0)

def run_server(port=8000):
    server = HTTPServer(('', port), EncryptionHandler)
    print(f'Serveur démarré sur le port {port}')
    
    # Configuration du gestionnaire de signal pour Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        print('\nServeur arrêté.')

if __name__ == '__main__':
    run_server()