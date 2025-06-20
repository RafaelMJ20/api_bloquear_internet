from flask import Flask, request, jsonify
from flask_cors import CORS
from librouteros import connect
import logging
import os

app = Flask(__name__)
CORS(app)  # Permite CORS para todos los dominios

# Configuración desde variables de entorno
MIKROTIK_API_HOST = os.getenv('MIKROTIK_API_HOST', 'https://f12c-2605-59c8-74d2-e610-00-c8b.ngrok-free.app')
USERNAME = os.getenv('MIKROTIK_USERNAME', 'admin')
PASSWORD = os.getenv('MIKROTIK_PASSWORD', '1234567890')
API_PORT = int(os.getenv('MIKROTIK_API_PORT', '8728'))

# Configuración de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_api_connection():
    """Establece conexión con MikroTik"""
    try:
        connection = connect(
            username=USERNAME,
            password=PASSWORD,
            host=MIKROTIK_API_HOST,
            port=API_PORT
        )
        logger.info("Conexión exitosa a MikroTik")
        return connection
    except Exception as e:
        logger.error(f"Error de conexión: {str(e)}")
        raise

@app.route('/internet', methods=['POST'])
def control_internet():
    """
    Controla acceso a internet por IP
    Body JSON esperado:
    {
        "ip_address": "192.168.88.100",
        "accion": "bloquear"  # o "permitir"
    }
    """
    data = request.get_json()
    
    # Validaciones básicas
    if not data:
        return jsonify({'error': 'Datos JSON requeridos'}), 400
    
    ip = data.get('ip_address')
    accion = data.get('accion')
    
    if not ip:
        return jsonify({'error': 'La dirección IP es requerida'}), 400
    
    if accion not in ['bloquear', 'permitir']:
        return jsonify({'error': 'Acción no válida. Use "bloquear" o "permitir"'}), 400

    try:
        api = get_api_connection()
        reglas = api.path('ip', 'firewall', 'filter')

        if accion == 'bloquear':
            # Verificar si ya está bloqueada
            for regla in reglas:
                if regla.get('src-address') == ip and regla.get('action') == 'drop':
                    return jsonify({'mensaje': f'La IP {ip} ya estaba bloqueada'}), 200

            # Crear nueva regla de bloqueo
            nueva_regla = reglas.add(
                chain='forward',
                src_address=ip,
                action='drop',
                comment='Bloqueo automático por API'
            )
            return jsonify({'mensaje': f'IP {ip} bloqueada exitosamente'}), 200

        elif accion == 'permitir':
            # Eliminar todas las reglas de bloqueo para esta IP
            eliminadas = 0
            for regla in reglas:
                if regla.get('src-address') == ip and regla.get('action') == 'drop':
                    reglas.remove(id=regla['.id'])
                    eliminadas += 1

            if eliminadas > 0:
                return jsonify({'mensaje': f'IP {ip} desbloqueada ({eliminadas} reglas eliminadas)'}), 200
            else:
                return jsonify({'mensaje': f'No había reglas de bloqueo para {ip}'}), 200

    except Exception as e:
        logger.error(f"Error en la operación: {str(e)}")
        return jsonify({'error': 'Error en el servidor'}), 500
    finally:
        if 'api' in locals():
            api.close()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
