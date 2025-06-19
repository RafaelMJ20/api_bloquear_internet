from flask import Flask, jsonify, request
from flask_cors import CORS
from requests.auth import HTTPBasicAuth
import requests
import logging
import os
import sys
import datetime

# =======================
# Configuración general
# =======================
app = Flask(__name__)
CORS(app)  # Habilita CORS

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# =======================
# Config MikroTik
# =======================
MIKROTIK_HOST = os.getenv('MIKROTIK_HOST', 'https://941b-200-68-173-6.ngrok-free.app ')
USERNAME = os.getenv('MIKROTIK_USER', 'admin')
PASSWORD = os.getenv('MIKROTIK_PASSWORD', '1234567890')
REQUEST_TIMEOUT = 10

# =======================
# Verificación conexión MikroTik
# =======================
def verify_mikrotik_connection():
    test_url = f"{MIKROTIK_HOST}/rest/system/resource"
    try:
        logger.info(f"Verificando conexión con MikroTik en: {MIKROTIK_HOST}")
        response = requests.get(test_url, auth=HTTPBasicAuth(USERNAME, PASSWORD), timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        logger.info("Conexión exitosa con MikroTik")
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Error al conectar con MikroTik: {str(e)}")
        return False

# =======================
# Ruta de bloqueo/desbloqueo
# =======================
@app.route('/internet', methods=['POST'])
def controlar_internet_por_ip():
    data = request.get_json()
    ip = data.get('ip_address')
    accion = data.get('accion')

    if not ip or accion not in ['bloquear', 'permitir']:
        return jsonify({'error': 'Se requiere ip_address y acción (bloquear o permitir)'}), 400

    if not verify_mikrotik_connection():
        return jsonify({'error': 'No se pudo conectar al MikroTik'}), 502

    firewall_url = f"{MIKROTIK_HOST}/rest/ip/firewall/filter"

    try:
        if accion == "bloquear":
            logger.info(f"Bloqueando IP: {ip}")
            response = requests.put(
                firewall_url,
                json={
                    "chain": "forward",
                    "src-address": ip,
                    "action": "drop",
                    "comment": "Bloqueado por API REST"
                },
                auth=HTTPBasicAuth(USERNAME, PASSWORD),
                timeout=REQUEST_TIMEOUT
            )
            response.raise_for_status()
            return jsonify({"message": f"Dispositivo con IP {ip} bloqueado correctamente"}), 200

        elif accion == "permitir":
            logger.info(f"Desbloqueando IP: {ip}")
            rules_response = requests.get(
                firewall_url,
                auth=HTTPBasicAuth(USERNAME, PASSWORD),
                timeout=REQUEST_TIMEOUT
            )
            rules_response.raise_for_status()
            reglas = rules_response.json()
            eliminadas = 0

            for regla in reglas:
                if regla.get("src-address") == ip and regla.get("action") == "drop":
                    rule_id = regla.get(".id")
                    delete_url = f"{firewall_url}/{rule_id}"
                    delete = requests.delete(
                        delete_url,
                        auth=HTTPBasicAuth(USERNAME, PASSWORD),
                        timeout=REQUEST_TIMEOUT
                    )
                    delete.raise_for_status()
                    eliminadas += 1

            return jsonify({"message": f"IP {ip} desbloqueada. Reglas eliminadas: {eliminadas}"}), 200

    except requests.exceptions.RequestException as e:
        logger.error(f"Error al modificar reglas de firewall: {str(e)}")
        return jsonify({'error': 'Fallo al modificar reglas de firewall: ' + str(e)}), 500

# =======================
# Ruta de verificación de estado
# =======================
@app.route('/status', methods=['GET'])
def service_status():
    connection_ok = verify_mikrotik_connection()
    return jsonify({
        'service': 'api-bloquear-internet',
        'mikrotik_host': MIKROTIK_HOST,
        'mikrotik_connection': connection_ok,
        'timestamp': datetime.datetime.now().isoformat()
    }), 200 if connection_ok else 503

# =======================
# Iniciar servidor
# =======================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    logger.info(f"Iniciando servidor en el puerto {port}")
    app.run(host='0.0.0.0', port=port)
