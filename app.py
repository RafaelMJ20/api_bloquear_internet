from flask import Flask, request, jsonify
from flask_cors import CORS
from librouteros import connect
import logging
import os

app = Flask(__name__)
CORS(app)

# Configuración MikroTik
MIKROTIK_API_HOST = '192.168.88.1'
USERNAME = 'admin'
PASSWORD = '1234567890'
API_PORT = 8728

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def get_api():
    """Conexión a MikroTik RouterOS"""
    try:
        connection = connect(
            username=USERNAME,
            password=PASSWORD,
            host=MIKROTIK_API_HOST,
            port=API_PORT
        )
        logger.debug("Conexión exitosa a MikroTik")
        return connection
    except Exception as e:
        logger.error(f"Error al conectar: {str(e)}")
        raise

@app.route('/internet', methods=['POST'])
def controlar_internet_por_ip():
    """
    Controlar acceso a internet por IP
    {
        "ip_address": "192.168.88.200",
        "accion": "bloquear"  # o "permitir"
    }
    """
    data = request.get_json()
    ip = data.get('ip_address')
    accion = data.get('accion')

    if not ip or accion not in ['bloquear', 'permitir']:
        return jsonify({'error': 'Se requiere ip_address y acción (bloquear o permitir)'}), 400

    try:
        api = get_api()
        reglas = api.path('ip', 'firewall', 'filter')

        if accion == 'bloquear':
            # Verificar si ya está bloqueado
            for regla in reglas:
                if regla.get('src-address') == ip and regla.get('action') == 'drop':
                    return jsonify({'message': f'La IP {ip} ya está bloqueada'}), 200

            # Agregar regla de bloqueo
            reglas.add(
                chain='forward',
                **{'src-address': ip},
                action='drop',
                comment='Bloqueado por API (IP)'
            )
            return jsonify({'message': f'Dispositivo con IP {ip} bloqueado correctamente'}), 200

        elif accion == 'permitir':
            eliminadas = 0
            for regla in reglas:
                if regla.get('src-address') == ip and regla.get('action') == 'drop':
                    reglas.remove(regla['.id'])
                    eliminadas += 1

            if eliminadas:
                return jsonify({'message': f'Dispositivo {ip} desbloqueado ({eliminadas} regla(s) eliminadas)'}), 200
            else:
                return jsonify({'message': f'No había reglas de bloqueo para {ip}'}), 200

    except Exception as e:
        logger.error(f"Error en el procedimiento: {str(e)}")
        return jsonify({'error': 'Error interno: ' + str(e)}), 500
        
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
