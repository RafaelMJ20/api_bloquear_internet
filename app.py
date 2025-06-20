from flask import Flask, jsonify, request
from flask_cors import CORS
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv
import requests
import logging
import datetime
import os

# Setup
load_dotenv()
app = Flask(__name__)
CORS(app)
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# MikroTik Config
MIKROTIK_HOST = os.getenv('MIKROTIK_HOST')
MIKROTIK_USER = os.getenv('MIKROTIK_USER')
MIKROTIK_PASSWORD = os.getenv('MIKROTIK_PASSWORD')
AUTH = HTTPBasicAuth(MIKROTIK_USER, MIKROTIK_PASSWORD)
TIMEOUT = 10

# Verificar conexión
def verify_connection():
    try:
        response = requests.get(f"{MIKROTIK_HOST}/rest/system/resource", auth=AUTH, timeout=TIMEOUT)
        response.raise_for_status()
        return True
    except Exception as e:
        logger.error(f"Conexión fallida con MikroTik: {e}")
        return False

# Programar acceso
@app.route('/programar', methods=['POST'])
def programar():
    data = request.get_json()
    ip = data.get('ip_address')
    hora_inicio = data.get('hora_inicio')
    hora_fin = data.get('hora_fin')
    dias = data.get('dias')

    if not all([ip, hora_inicio, hora_fin, dias]):
        return jsonify({'error': 'Faltan datos: ip_address, hora_inicio, hora_fin, dias'}), 400

    comment_base = f"Programado-{ip}"
    fecha_hoy = datetime.datetime.now().strftime('%Y-%m-%d')  # Formato para REST

    try:
        if not verify_connection():
            return jsonify({'error': 'No se pudo conectar con MikroTik'}), 500

        # Crear reglas de firewall
        for rule in [
            {
                "chain": "forward",
                "src-address": ip,
                "action": "drop",
                "comment": f"{comment_base}-bloqueo",
                "disabled": False
            },
            {
                "chain": "forward",
                "src-address": ip,
                "action": "accept",
                "comment": f"{comment_base}-acceso",
                "disabled": True
            }
        ]:
            requests.post(f"{MIKROTIK_HOST}/rest/ip/firewall/filter", json=rule, auth=AUTH)

        # Crear tareas en el scheduler
        scheduler_tasks = [
            {
                "name": f"activar-{ip}",
                "start-time": hora_inicio,
                "start-date": fecha_hoy,
                "interval": "1d",
                "on-event": f"/ip/firewall/filter enable [find comment=\"{comment_base}-acceso\"];\n/ip/firewall/filter disable [find comment=\"{comment_base}-bloqueo\"]",
                "policy": "read,write,test",
                "disabled": False,
                "comment": f"Activar acceso {ip}"
            },
            {
                "name": f"desactivar-{ip}",
                "start-time": hora_fin,
                "start-date": fecha_hoy,
                "interval": "1d",
                "on-event": f"/ip/firewall/filter disable [find comment=\"{comment_base}-acceso\"];\n/ip/firewall/filter enable [find comment=\"{comment_base}-bloqueo\"]",
                "policy": "read,write,test",
                "disabled": False,
                "comment": f"Desactivar acceso {ip}"
            }
        ]

        for task in scheduler_tasks:
            requests.post(f"{MIKROTIK_HOST}/rest/system/scheduler", json=task, auth=AUTH)

        return jsonify({'message': f'Reglas programadas exitosamente para {ip}'}), 200

    except Exception as e:
        logger.exception("Error al programar reglas")
        return jsonify({'error': str(e)}), 500

# Prueba simple
@app.route('/test', methods=['GET'])
def test_connection():
    return jsonify({'mikrotik_online': verify_connection()}), 200

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
