from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import stripe
from stripe._error import CardError, AuthenticationError, StripeError
import os
import requests
import secrets
import hashlib
import logging
import random
import json
import re
import base64
import string
import time
from datetime import datetime, timedelta, date
from functools import wraps
from models import db, Config, User, CheckHistory
from gates.braintree3d import verify_braintree_card
from gates.stripecharged import verify_stripe_charge
from gates.stripe_auth import verify_stripe_auth

app = Flask(__name__)

# Configuración de la aplicación
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Configuración de sesión segura
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'  # Solo HTTPS en producción
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Previene acceso desde JavaScript
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protección CSRF
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)  # Sesión expira en 24h

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuración de la base de datos
# Para desarrollo local: SQLite
# Para producción: PostgreSQL (se detecta automáticamente desde DATABASE_URL)
database_url = os.environ.get('DATABASE_URL')

if database_url:
    # Fix para Heroku/Render que usan postgres:// en lugar de postgresql://
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
else:
    # SQLite para desarrollo local
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///snoop_dogg_checker.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
}

# Inicializar base de datos
db.init_app(app)

# Función para inicializar base de datos (se ejecuta al iniciar la app)
def init_db():
    """Inicializa la base de datos creando todas las tablas si no existen"""
    with app.app_context():
        db.create_all()
        print("✅ Base de datos inicializada")
        
        # Migración: Agregar columna max_checks si no existe (PostgreSQL)
        try:
            from sqlalchemy import text
            inspector = db.inspect(db.engine)
            columns = [col['name'] for col in inspector.get_columns('users')]
            
            if 'max_checks' not in columns:
                print("📝 Migrando BD: Agregando columna max_checks...")
                with db.engine.connect() as conn:
                    conn.execute(text('ALTER TABLE users ADD COLUMN max_checks INTEGER DEFAULT 50 NOT NULL'))
                    conn.commit()
                print("✅ Columna max_checks agregada exitosamente")
        except Exception as e:
            print(f"⚠️ Error en migración (puede ser normal si es SQLite): {e}")
        
        # Inicializar configuración por defecto si no existe
        if Config.query.count() == 0:
            print("📝 Inicializando configuración por defecto...")
            default_configs = [
                ('admin_password', 'Mon11$$99'),
                ('stripe_pk', ''),
                ('stripe_sk', ''),
                ('daily_limit', '50'),
                ('maintenance_mode', 'false'),
                ('gate_auth_enabled', 'true'),
                ('gate_charge_enabled', 'false'),
                ('charge_amount_eur', '1.00')
            ]
            for key, value in default_configs:
                config = Config(key=key, value=value)
                db.session.add(config)
            
            # Inicializar gates dinámicos como JSON
            default_gates = {
                'auth': {
                    'enabled': True,
                    'name': 'Auth',
                    'description': 'Sin Cargo',
                    'icon': '🔓',
                    'color': '#667eea'
                },
                'stripe_auth': {
                    'enabled': True,
                    'name': 'Stripe Auth',
                    'description': 'Auth Gate',
                    'icon': '🌊',
                    'color': '#06b6d4'
                },
                'charge': {
                    'enabled': False,
                    'name': 'Charged',
                    'description': '€1.00',
                    'icon': '💳',
                    'color': '#f093fb',
                    'amount': 1.00,
                    'currency': 'EUR'
                },
                'braintree': {
                    'enabled': True,
                    'name': 'Braintree',
                    'description': '3D Secure',
                    'icon': '🔐',
                    'color': '#10b981'
                }
            }
            gates_config = Config(key='gates_config', value=json.dumps(default_gates))
            db.session.add(gates_config)
            
            db.session.commit()
            print("✅ Configuración inicial creada")
            print("🔑 Password admin por defecto: admin123")
            print("⚠️ CAMBIA LA CONTRASEÑA EN EL PANEL ADMIN")

# Ejecutar inicialización al importar el módulo
init_db()

# ==================== SEGURIDAD ====================

# Headers de seguridad HTTP
@app.after_request
def set_security_headers(response):
    """Agrega headers de seguridad a todas las respuestas"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Content Security Policy
    csp = "default-src 'self'; " \
          "script-src 'self' 'unsafe-inline' https://js.stripe.com; " \
          "style-src 'self' 'unsafe-inline'; " \
          "img-src 'self' data: https:; " \
          "font-src 'self' data:; " \
          "connect-src 'self' https://api.stripe.com https://lookup.binlist.net; " \
          "frame-src https://js.stripe.com https://hooks.stripe.com;"
    response.headers['Content-Security-Policy'] = csp
    
    return response

# Rate limiting mejorado (compatible con Cloudflare/proxies)
from collections import defaultdict
import time

# Almacén de intentos por IP
rate_limit_storage = defaultdict(list)

# Función para limpiar storage antiguo periódicamente
def cleanup_rate_limit_storage():
    """Limpia solicitudes antiguas del storage de rate limiting"""
    now = time.time()
    ips_to_remove = []
    
    for ip, requests in rate_limit_storage.items():
        # Limpiar solicitudes más antiguas de 5 minutos
        rate_limit_storage[ip] = [req_time for req_time in requests if (now - req_time) < 300]
        
        # Si la lista está vacía, marcar para eliminar
        if not rate_limit_storage[ip]:
            ips_to_remove.append(ip)
    
    # Eliminar IPs sin solicitudes recientes
    for ip in ips_to_remove:
        del rate_limit_storage[ip]

def get_real_ip():
    """Obtiene la IP real del usuario considerando proxies y Cloudflare"""
    # Cloudflare pone la IP real en CF-Connecting-IP
    if request.headers.get('CF-Connecting-IP'):
        return request.headers.get('CF-Connecting-IP')
    
    # Otros proxies usan X-Forwarded-For (primera IP es la real)
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    
    # X-Real-IP es usado por Nginx y otros
    if request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    
    # Fallback a remote_addr
    return request.remote_addr

def rate_limit(max_requests=10, window_seconds=60, skip_for_development=False):
    """Decorador para rate limiting por IP real (compatible con Cloudflare)"""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # En desarrollo, opcionalmente saltar rate limiting
            if skip_for_development and os.environ.get('FLASK_ENV') == 'development':
                return f(*args, **kwargs)
            
            # Limpiar storage periódicamente (cada 100 requests aproximadamente)
            if random.random() < 0.01:  # 1% de probabilidad
                cleanup_rate_limit_storage()
            
            ip = get_real_ip()
            
            # Si la IP es None o vacía (puede pasar en desarrollo), usar sesión como fallback
            if not ip or ip == '127.0.0.1' or ip == 'localhost':
                # Usar sesión ID como fallback para evitar que todas las requests se agrupen
                session_id = session.get('session_id') or session.get('_id') or request.cookies.get('session') or str(random.randint(1000, 9999))
                ip = f'session_{session_id}'
            
            now = time.time()
            
            # Inicializar lista si no existe
            if ip not in rate_limit_storage:
                rate_limit_storage[ip] = []
            
            # Limpiar intentos antiguos (solo los que están dentro de la ventana de tiempo)
            rate_limit_storage[ip] = [
                req_time for req_time in rate_limit_storage[ip] 
                if (now - req_time) < window_seconds
            ]
            
            # Excepción especial: nunca bloquear get_config (es solo lectura)
            if 'get_config' in request.path:
                rate_limit_storage[ip].append(now)
                return f(*args, **kwargs)
            
            # Verificar límite (solo si hay solicitudes en la ventana)
            current_count = len(rate_limit_storage[ip])
            if current_count >= max_requests:
                # Log más detallado para debugging
                endpoint = request.endpoint or request.path or 'unknown'
                logger.warning(f"Rate limit exceeded - IP: {ip}, Endpoint: {endpoint}, Requests: {current_count}/{max_requests} in {window_seconds}s, Path: {request.path}")
                
                return jsonify({
                    'success': False,
                    'error': 'Demasiadas solicitudes. Intenta de nuevo en un momento.',
                    'debug_info': {
                        'endpoint': endpoint,
                        'requests': current_count,
                        'limit': max_requests,
                        'window': window_seconds,
                        'path': request.path
                    }
                }), 429
            
            # Agregar intento actual (solo si no se excedió el límite)
            rate_limit_storage[ip].append(now)
            
            return f(*args, **kwargs)
        return wrapped
    return decorator

# Sanitización de inputs
def sanitize_input(value, max_length=100):
    """Limpia y valida inputs de usuario"""
    if not value:
        return ''
    value = str(value).strip()
    # Remover caracteres peligrosos
    dangerous_chars = ['<', '>', '"', "'", '&', '\\', ';']
    for char in dangerous_chars:
        value = value.replace(char, '')
    return value[:max_length]

# Logging de eventos de seguridad
def log_security_event(event_type, details, user_id=None):
    """Registra eventos de seguridad para auditoría"""
    ip = get_real_ip()
    user_agent = request.headers.get('User-Agent', 'Unknown')
    logger.warning(f"SECURITY [{event_type}] IP: {ip} | User: {user_id} | Details: {details} | UA: {user_agent[:100]}")

# Funciones de configuración usando base de datos
def get_config(key, default=None):
    """Obtiene un valor de configuración de la base de datos"""
    config = Config.query.filter_by(key=key).first()
    if config:
        value = config.value
        # Convertir valores booleanos
        if value == 'true' or value == 'True':
            return True
        elif value == 'false' or value == 'False':
            return False
        # Intentar convertir a número
        try:
            if '.' in value:
                return float(value)
            return int(value)
        except:
            return value
    return default

def set_config(key, value):
    """Establece un valor de configuración en la base de datos"""
    config = Config.query.filter_by(key=key).first()
    if config:
        config.value = str(value)
    else:
        config = Config(key=key, value=str(value))
        db.session.add(config)
    db.session.commit()

def load_config():
    """Carga toda la configuración como un diccionario (para compatibilidad)"""
    configs = Config.query.all()
    config_dict = {}
    for config in configs:
        value = config.value
        # Convertir valores
        if value == 'true' or value == 'True':
            value = True
        elif value == 'false' or value == 'False':
            value = False
        else:
            try:
                if '.' in value:
                    value = float(value)
                else:
                    value = int(value)
            except:
                pass
        config_dict[config.key] = value
    
    # Agregar valores por defecto si no existen (para gates)
    if 'gate_auth_enabled' not in config_dict:
        config_dict['gate_auth_enabled'] = True
    else:
        # Asegurar que sea booleano
        if isinstance(config_dict['gate_auth_enabled'], str):
            config_dict['gate_auth_enabled'] = config_dict['gate_auth_enabled'].lower() in ['true', '1', 'yes']
    
    if 'gate_charge_enabled' not in config_dict:
        config_dict['gate_charge_enabled'] = False
    else:
        # Asegurar que sea booleano
        if isinstance(config_dict['gate_charge_enabled'], str):
            config_dict['gate_charge_enabled'] = config_dict['gate_charge_enabled'].lower() in ['true', '1', 'yes']
    
    if 'charge_amount_eur' not in config_dict:
        config_dict['charge_amount_eur'] = '1.00'
    
    return config_dict

def get_gates_config():
    """Obtiene la configuración de gates dinámicos desde la BD"""
    gates_json = get_config('gates_config', None)
    if gates_json:
        try:
            if isinstance(gates_json, str):
                return json.loads(gates_json)
            return gates_json
        except:
            pass
    
    # Valores por defecto si no existe
    return {
        'auth': {
            'enabled': True,
            'name': 'Auth',
            'description': 'Sin Cargo',
            'icon': '🔓',
            'color': '#667eea'
        },
        'stripe_auth': {
            'enabled': True,
            'name': 'Stripe Auth',
            'description': 'Auth Gate',
            'icon': '🌊',
            'color': '#06b6d4'
        },
        'charge': {
            'enabled': False,
            'name': 'Charged',
            'description': '€1.00',
            'icon': '💳',
            'color': '#f093fb',
            'amount': 1.00,
            'currency': 'EUR'
        },
        'braintree': {
            'enabled': True,
            'name': 'Braintree',
            'description': '3D Secure',
            'icon': '🔐',
            'color': '#10b981'
        }
    }

def set_gates_config(gates_dict):
    """Guarda la configuración de gates dinámicos en la BD"""
    set_config('gates_config', json.dumps(gates_dict))

# Generar hash único de dispositivo
def get_device_fingerprint(user_agent, ip):
    """Genera un hash único basado en IP y User-Agent"""
    fingerprint_string = f"{ip}|{user_agent}"
    return hashlib.sha256(fingerprint_string.encode()).hexdigest()

# Decorador para verificar admin
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Decorador para verificar key de usuario
def key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Verificar si es una petición AJAX/JSON (GET para /get_config, POST para /verify)
        is_ajax = (
            request.headers.get('Content-Type') == 'application/json' or 
            request.headers.get('X-Requested-With') == 'XMLHttpRequest' or
            request.path.startswith('/checker/verify') or
            request.path.startswith('/checker/get_config')
        )
        
        user_key = session.get('user_key')
        if not user_key:
            if is_ajax:
                return jsonify({'success': False, 'error': 'No autenticado. Por favor, inicia sesión.'}), 401
            return redirect(url_for('checker_auth'))
        
        # Verificar que la key sigue siendo válida
        user = User.query.filter_by(key=user_key).first()
        if not user:
            session.clear()
            if is_ajax:
                return jsonify({'success': False, 'error': 'Usuario no encontrado. Sesión expirada.'}), 401
            return redirect(url_for('checker_auth'))
        
        if not user.active:
            session.clear()
            if is_ajax:
                return jsonify({'success': False, 'error': 'Tu key ha sido desactivada. Contacta al administrador.'}), 403
            return redirect(url_for('checker_auth'))
        
        return f(*args, **kwargs)
    return decorated_function

# Función para parsear errores de Stripe
def parse_error_details(error):
    """Parsea los errores de Stripe para obtener detalles específicos."""
    error_code = getattr(error, 'code', None)
    error_message = str(error)
    user_message = getattr(error, 'user_message', None) or error_message
    
    error_details = {
        'code': error_code,
        'type': 'unknown',
        'message': user_message,
        'details': {}
    }
    
    # Detectar tipos específicos de errores
    error_lower = error_message.lower()
    
    if error_code:
        if 'card_declined' in error_code.lower():
            error_details['type'] = 'card_declined'
            error_details['details']['reason'] = error_code
            if 'insufficient_funds' in error_code:
                error_details['message'] = '❌ Pago rechazado - Fondos insuficientes'
            elif 'lost_card' in error_code:
                error_details['message'] = '❌ Pago rechazado - Tarjeta reportada como perdida'
            elif 'stolen_card' in error_code:
                error_details['message'] = '❌ Pago rechazado - Tarjeta reportada como robada'
            elif 'expired_card' in error_code:
                error_details['message'] = '❌ Pago rechazado - Tarjeta expirada'
            elif 'incorrect_cvc' in error_code:
                error_details['message'] = '❌ Pago rechazado - CVV incorrecto'
            elif error_code == 'card_declined':
                # Caso genérico - usar el mensaje del usuario si está disponible
                if user_message and user_message != error_message:
                    error_details['message'] = f'❌ Pago rechazado: {user_message}'
                else:
                    error_details['message'] = '❌ Pago rechazado - El banco rechazó la transacción. Verifica los datos o contacta a tu banco.'
        elif 'incorrect_cvc' in error_code.lower():
            error_details['type'] = 'cvv_error'
            error_details['message'] = 'CVV incorrecto'
        elif 'incorrect_number' in error_code.lower():
            error_details['type'] = 'card_number_error'
            error_details['message'] = 'Número de tarjeta inválido'
    
    return error_details

# ==================== RUTAS ADMIN ====================

@app.route('/admin/login', methods=['GET', 'POST'])
@rate_limit(max_requests=20, window_seconds=60)  # 20 intentos por minuto
def admin_login():
    if request.method == 'POST':
        password = request.json.get('password', '').strip()
        admin_password = get_config('admin_password', 'admin123')
        
        if password == admin_password:
            session['is_admin'] = True
            log_security_event('ADMIN_LOGIN_SUCCESS', 'Admin login successful')
            logger.info(f"Admin login successful from IP: {get_real_ip()}")
            return jsonify({'success': True})
        else:
            log_security_event('ADMIN_LOGIN_FAILED', f'Failed attempt with password length: {len(password)}')
            return jsonify({'success': False, 'error': 'Contraseña incorrecta'}), 401
    
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('is_admin', None)
    return redirect(url_for('admin_login'))

@app.route('/admin')
@admin_required
def admin_panel():
    return render_template('admin.html')

@app.route('/admin/get_config', methods=['GET'])
@admin_required
def get_admin_config():
    config = load_config()
    gates_config = get_gates_config()
    
    # Contar estadísticas
    total_keys = User.query.count()
    active_keys = User.query.filter_by(active=True).count()
    
    return jsonify({
        'config': config,
        'gates_config': gates_config,
        'stats': {
            'total_keys': total_keys,
            'active_keys': active_keys
        }
    })

@app.route('/admin/update_config', methods=['POST'])
@admin_required
def update_config():
    data = request.json
    
    # Actualizar configuración general
    if 'admin_password' in data:
        set_config('admin_password', data['admin_password'])
    if 'stripe_pk' in data:
        set_config('stripe_pk', data['stripe_pk'])
    if 'stripe_sk' in data:
        set_config('stripe_sk', data['stripe_sk'])
        # Actualizar la API key de Stripe
        stripe.api_key = data['stripe_sk']
    if 'max_checks_per_day' in data:
        set_config('max_checks_per_day', int(data['max_checks_per_day']))
    if 'maintenance_mode' in data:
        # Asegurar que se guarde como booleano
        set_config('maintenance_mode', 'true' if data['maintenance_mode'] else 'false')
    
    # Actualizar gates dinámicamente
    if 'gates_config' in data:
        gates_config = data['gates_config']
        # Validar que sea un diccionario
        if isinstance(gates_config, dict):
            set_gates_config(gates_config)
    else:
        # Mantener compatibilidad con configuración antigua
        gates_config = get_gates_config()
        
        if 'gate_auth_enabled' in data:
            if 'auth' not in gates_config:
                gates_config['auth'] = {}
            gates_config['auth']['enabled'] = bool(data['gate_auth_enabled'])
        
        if 'gate_charge_enabled' in data:
            if 'charge' not in gates_config:
                gates_config['charge'] = {}
            gates_config['charge']['enabled'] = bool(data['gate_charge_enabled'])
        
        if 'charge_amount_eur' in data:
            if 'charge' not in gates_config:
                gates_config['charge'] = {}
            gates_config['charge']['amount'] = float(data['charge_amount_eur'])
        
        # Guardar configuración actualizada
        set_gates_config(gates_config)
    
    return jsonify({'success': True})

@app.route('/admin/get_keys', methods=['GET'])
@admin_required
def get_keys():
    users = User.query.all()
    
    # Formatear keys para el frontend
    keys_list = []
    for user in users:
        keys_list.append({
            'key': user.key,
            'name': user.name,
            'active': user.active,
            'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S') if user.created_at else '',
            'checks_today': user.checks_today,
            'max_checks': user.max_checks,  # Límite personalizado de cada key
            'last_check_date': user.last_check_date.strftime('%Y-%m-%d') if user.last_check_date else '',
            'device_fingerprint': user.device_fingerprint or 'No registrado',
            'last_ip': user.last_ip or 'N/A'
        })
    
    return jsonify({'keys': keys_list})

@app.route('/admin/generate_key', methods=['POST'])
@admin_required
def generate_key():
    data = request.json
    name = data.get('name', 'Usuario')
    max_checks = int(data.get('max_checks', 50))  # Límite personalizado o 50 por defecto
    
    # Validar límite
    if max_checks < 1 or max_checks > 10000:
        return jsonify({
            'success': False,
            'error': 'El límite debe estar entre 1 y 10000'
        }), 400
    
    # Generar key única
    new_key = secrets.token_urlsafe(32)
    
    # Crear nuevo usuario
    user = User(
        key=new_key,
        name=name,
        active=True,
        created_at=datetime.now(),
        checks_today=0,
        last_check_date=None,
        max_checks=max_checks,
        device_fingerprint=None,
        last_ip=None
    )
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'key': new_key,
        'name': name,
        'max_checks': max_checks
    })

@app.route('/admin/toggle_key', methods=['POST'])
@admin_required
def toggle_key():
    data = request.json
    key = data.get('key')
    
    user = User.query.filter_by(key=key).first()
    
    if user:
        user.active = not user.active
        db.session.commit()
        return jsonify({'success': True, 'active': user.active})
    
    return jsonify({'success': False, 'error': 'Key no encontrada'}), 404

@app.route('/admin/delete_key', methods=['POST'])
@admin_required
def delete_key():
    data = request.json
    key = data.get('key')
    
    user = User.query.filter_by(key=key).first()
    
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'error': 'Key no encontrada'}), 404

@app.route('/admin/reset_key_device', methods=['POST'])
@admin_required
def reset_key_device():
    """Resetea el dispositivo registrado de una key"""
    data = request.json
    key = data.get('key')
    
    user = User.query.filter_by(key=key).first()
    
    if user:
        user.device_fingerprint = None
        user.last_ip = None
        db.session.commit()
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'error': 'Key no encontrada'}), 404


# ==================== RUTAS CHECKER (USUARIOS) ====================

@app.route('/')
def index():
    return redirect(url_for('checker_auth'))

@app.route('/checker/auth', methods=['GET', 'POST'])
@rate_limit(max_requests=30, window_seconds=60)  # 30 intentos por minuto
def checker_auth():
    if request.method == 'POST':
        key = sanitize_input(request.json.get('key', ''), max_length=64)
        
        if not key or len(key) < 32:
            log_security_event('INVALID_KEY_FORMAT', f'Key length: {len(key)}')
            return jsonify({'success': False, 'error': 'Proporciona una key válida'}), 400
        
        # Verificar que la key existe
        user = User.query.filter_by(key=key).first()
        
        if not user:
            log_security_event('KEY_NOT_FOUND', f'Attempted key: {key[:8]}...')
            return jsonify({'success': False, 'error': 'Key inválida'}), 401
        
        # Verificar que la key está activa
        if not user.active:
            log_security_event('KEY_DISABLED', f'User: {user.name}', user_id=user.id)
            return jsonify({'success': False, 'error': 'Key desactivada'}), 401
        
        # Obtener fingerprint del dispositivo
        user_agent = request.headers.get('User-Agent', '')
        ip_address = get_real_ip()
        current_fingerprint = get_device_fingerprint(user_agent, ip_address)
        
        # Verificar si este dispositivo ya está vinculado a otra key activa con checks disponibles
        existing_user = User.query.filter(
            User.device_fingerprint == current_fingerprint,
            User.key != key,
            User.active == True
        ).first()
        
        if existing_user:
            # Verificar si la key existente tiene checks disponibles
            today = date.today()
            if existing_user.last_check_date == today:
                checks_remaining = existing_user.max_checks - existing_user.checks_today
            else:
                checks_remaining = existing_user.max_checks
            
            if checks_remaining > 0:
                log_security_event('DEVICE_ALREADY_LINKED', f'Device linked to: {existing_user.name}, has {checks_remaining} checks remaining')
                return jsonify({
                    'success': False,
                    'error': f'Tu dispositivo ya está vinculado a otra key activa con {checks_remaining} checks disponibles. Usa esa key o contacta al administrador.'
                }), 403
            else:
                # La key anterior no tiene checks disponibles, permitir cambio
                # Desvincular dispositivo de la key anterior
                existing_user.device_fingerprint = None
                existing_user.last_ip = None
                db.session.commit()
                logger.info(f"Device unlinked from user: {existing_user.name} (no checks remaining)")
        
        # Si la key ya tiene un dispositivo registrado
        if user.device_fingerprint:
            if user.device_fingerprint != current_fingerprint:
                # El fingerprint cambió, pero como está usando SU PROPIA key, actualizamos el fingerprint
                # Esto permite que el usuario acceda si cambió de red/IP o el User-Agent cambió ligeramente
                logger.info(f"Fingerprint actualizado para usuario {user.name}: IP o User-Agent cambió")
                user.device_fingerprint = current_fingerprint
                user.last_ip = ip_address
                db.session.commit()
                logger.info(f"Device fingerprint updated for user: {user.name} (ID: {user.id})")
        else:
            # Registrar dispositivo por primera vez
            user.device_fingerprint = current_fingerprint
            user.last_ip = ip_address
            db.session.commit()
            logger.info(f"Device registered for user: {user.name} (ID: {user.id})")
        
        # Guardar key en sesión
        session['user_key'] = key
        session['user_name'] = user.name
        log_security_event('USER_LOGIN_SUCCESS', f'User: {user.name}', user_id=user.id)
        
        return jsonify({'success': True})
    
    # Si ya tiene una sesión válida, redirigir al checker
    if session.get('user_key'):
        return redirect(url_for('checker'))
    
    return render_template('checker_auth.html')

@app.route('/checker/logout')
def checker_logout():
    session.clear()
    return redirect(url_for('checker_auth'))

@app.route('/checker')
@key_required
def checker():
    # No aplicar rate limiting a la página principal del checker
    config = load_config()
    
    # Verificar modo mantenimiento
    if config.get('maintenance_mode', False):
        return render_template('maintenance.html')
    
    return render_template('checker.html')

@app.route('/checker/get_config', methods=['GET'])
# @rate_limit deshabilitado temporalmente para /checker/get_config ya que es solo lectura y se llama frecuentemente
@key_required
def checker_get_config():
    """Endpoint para que el checker obtenga la configuración de Stripe PK y gates"""
    try:
        user_key = session.get('user_key')
        user = User.query.filter_by(key=user_key).first()
        
        if not user:
            return jsonify({'success': False, 'error': 'Usuario no encontrado'}), 404
        
        # Calcular checks restantes usando el límite personalizado del usuario
        today = date.today()
        if user.last_check_date != today:
            checks_today = 0
        else:
            checks_today = user.checks_today
        
        checks_remaining = user.max_checks - checks_today
        
        # Obtener configuración de gates dinámicos
        gates_config = get_gates_config()
        
        # Para compatibilidad con charge, mantener amount
        if 'charge' in gates_config and 'amount' not in gates_config['charge']:
            charge_amount_eur = float(get_config('charge_amount_eur', '1.00'))
            gates_config['charge']['amount'] = charge_amount_eur
        
        return jsonify({
            'success': True,
            'stripe_pk': get_config('stripe_pk', ''),
            'checks_remaining': checks_remaining,
            'max_checks': user.max_checks,
            'gates': gates_config
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500



@app.route('/checker/verify_auth', methods=['POST'])
@rate_limit(max_requests=30, window_seconds=60)  # 30 checks por minuto por IP
@key_required
def checker_verify_auth():
    """Endpoint para verificar tarjetas en modo Auth usando charitywater.org (sin cargo)"""
    try:
        config = load_config()
        
        # Verificar modo mantenimiento
        if config.get('maintenance_mode', False):
            return jsonify({
                'success': False,
                'error': 'Sistema en mantenimiento'
            }), 503
        
        # Verificar si el gate Auth está habilitado
        gates_config = get_gates_config()
        if not gates_config.get('auth', {}).get('enabled', True):
            return jsonify({
                'success': False,
                'error': '⚠️ Gate Auth está actualmente en mantenimiento.',
                'status': 'maintenance'
            }), 503
        
        # Obtener información del usuario
        user_key = session.get('user_key')
        user = User.query.filter_by(key=user_key).first()
        
        if not user:
            return jsonify({
                'success': False,
                'error': 'Usuario no encontrado'
            }), 404
        
        # Verificar límite diario
        today = date.today()
        if user.last_check_date != today:
            user.checks_today = 0
            user.last_check_date = today
            db.session.commit()
        
        if user.checks_today >= user.max_checks:
            return jsonify({
                'success': False,
                'error': f'Has alcanzado el límite de {user.max_checks} checks. Contacta al administrador.'
            }), 429
        
        # Obtener datos de la tarjeta (DATOS DIRECTOS, NO payment_method_id)
        data = request.json
        card_number = data.get('card_number', '').strip().replace(' ', '').replace('-', '')
        exp_month = data.get('exp_month', '').strip()
        exp_year = data.get('exp_year', '').strip()
        cvv = data.get('cvv', '').strip()
        
        # Validar que se proporcionaron todos los datos
        if not all([card_number, exp_month, exp_year, cvv]):
            return jsonify({
                'success': False,
                'error': 'Datos de tarjeta incompletos. Proporciona: card_number, exp_month, exp_year, cvv'
            }), 400
        
        # Formatear año (asegurar formato correcto)
        if len(str(exp_year)) == 2:
            exp_year = '20' + str(exp_year)
        
        # Crear registro de historial
        check_record = CheckHistory(
            user_id=user.id,
            payment_method_id=None,
            status='pending',
            mode='auth'
        )
        db.session.add(check_record)
        db.session.commit()
        
        try:
            # Obtener user agent
            user_agent = request.headers.get('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            
            # USAR EL GATE stripe_auth.py DIRECTAMENTE
            result = verify_stripe_auth(
                card_number=card_number,
                exp_month=str(exp_month).zfill(2),
                exp_year=str(exp_year),
                cvv=str(cvv),
                user_agent=user_agent
            )
            
            # Incrementar contador
            user.checks_today += 1
            
            # Actualizar historial según el resultado
            if result.get('success'):
                check_record.status = 'approved'
                details = result.get('details', {})
                card_details = details.get('card', {})
                check_record.card_last4 = card_number[-4:] if len(card_number) >= 4 else ''
                check_record.card_brand = card_details.get('brand', '')
                check_record.card_type = card_details.get('type', '')
                check_record.card_country = card_details.get('country', '')
            else:
                # Distinguir entre error de merchant y error de tarjeta
                error_code = result.get('details', {}).get('error_code', result.get('status', 'error'))
                if error_code in ['merchant_account_error', 'merchant_restriction']:
                    check_record.status = 'error'
                    # No incrementar contador si es error del merchant
                    user.checks_today -= 1
                else:
                    check_record.status = 'declined'
                check_record.error_code = error_code
            
            db.session.commit()
            
            # Obtener información del BIN
            bin_info = result.get('details', {}).get('bin_info')
            if not bin_info:
                # Si no hay bin_info, intentar obtenerlo desde el número de tarjeta
                bin_number = card_number[:6] if len(card_number) >= 6 else ''
                if bin_number:
                    try:
                        bin_response = requests.get(
                            f"https://lookup.binlist.net/{bin_number}",
                            headers={'Accept-Version': '3'},
                            timeout=5
                        )
                        if bin_response.status_code == 200:
                            bin_info = bin_response.json()
                            if not bin_info.get('country'):
                                bin_info = None
                    except Exception:
                        bin_info = None
            
            # Preparar respuesta
            success = result.get('success', False)
            status = result.get('status', 'error')
            message = result.get('message', '')
            
            # Si no hay mensaje, generar uno basado en el status
            if not message or message.strip() == '':
                if success:
                    message = 'Tarjeta válida ✅ (Auth - Sin Cargo)'
                elif status == 'declined':
                    message = 'Tarjeta rechazada ❌'
                elif status == 'error':
                    message = 'Error al procesar la tarjeta'
                else:
                    message = f'Error: {status}'
            
            response_data = {
                'success': success,
                'message': message,
                'status': status,
                'mode': 'auth',
                'checks_remaining': user.max_checks - user.checks_today,
                'details': {
                    'card': result.get('details', {}).get('card', {}),
                    'bin_info': bin_info
                }
            }
            
            # Si hay error, asegurarse de que esté en el campo 'error' también
            if not success:
                response_data['error'] = message
                # Si es error de merchant, retornar 503 en lugar de 400
                if status == 'error':
                    return jsonify(response_data), 503
            
            return jsonify(response_data)
        
        except Exception as e:
            user.checks_today += 1
            if 'check_record' in locals() and check_record:
                check_record.status = 'error'
                check_record.error_code = 'unexpected_error'
            db.session.commit()
            
            error_msg = str(e) if e else 'Error desconocido'
            logger.error(f'Error en verify_auth: {error_msg}', exc_info=True)
            
            return jsonify({
                'success': False,
                'error': f'Error al procesar tarjeta: {error_msg}',
                'message': f'Error al procesar tarjeta: {error_msg}',
                'status': 'error',
                'mode': 'auth',
                'checks_remaining': user.max_checks - user.checks_today
            }), 500
    
    except Exception as e:
        error_msg = str(e) if e else 'Error desconocido en el servidor'
        logger.error(f'Error general en verify_auth: {error_msg}', exc_info=True)
        return jsonify({
            'success': False,
            'error': f'Error al procesar la solicitud: {error_msg}',
            'message': f'Error al procesar la solicitud: {error_msg}',
            'status': 'error'
        }), 500

@app.route('/checker/verify_charge', methods=['POST'])
@rate_limit(max_requests=3, window_seconds=120)
@key_required
def checker_verify_charge():
    """Endpoint para verificar tarjetas en modo Charge usando charitywater.org"""
    try:
        config = load_config()
        
        # Verificar modo mantenimiento
        if config.get('maintenance_mode', False):
            return jsonify({
                'success': False,
                'error': 'Sistema en mantenimiento'
            }), 503
        
        # Verificar si el gate Charged está habilitado
        gate_charge_enabled = config.get('gate_charge_enabled', False)
        if gate_charge_enabled == 'false' or gate_charge_enabled == False:
            return jsonify({
                'success': False,
                'error': '⚠️ Gate Charged está actualmente en mantenimiento. El administrador lo ha desactivado temporalmente.',
                'status': 'maintenance'
            }), 503
        
        # Obtener información del usuario
        user_key = session.get('user_key')
        user = User.query.filter_by(key=user_key).first()
        
        if not user:
            return jsonify({
                'success': False,
                'error': 'Usuario no encontrado'
            }), 404
        
        # Verificar límite diario
        today = date.today()
        if user.last_check_date != today:
            user.checks_today = 0
            user.last_check_date = today
            db.session.commit()
        
        if user.checks_today >= user.max_checks:
            return jsonify({
                'success': False,
                'error': f'Has alcanzado el límite de {user.max_checks} checks. Contacta al administrador para obtener una nueva key o aumentar tu límite.'
            }), 429
        
        # Verificar delay mínimo entre verificaciones (reducido a 5 segundos)
        last_check = CheckHistory.query.filter_by(
            user_id=user.id,
            mode='charge'
        ).order_by(CheckHistory.created_at.desc()).first()
        
        time_since_last = 0
        if last_check and last_check.created_at:
            time_since_last = (datetime.utcnow() - last_check.created_at).total_seconds()
            min_delay = 5  # Reducido de 60 a 5 segundos
            if time_since_last < min_delay:
                wait_time = min_delay - time_since_last
                return jsonify({
                    'success': False,
                    'error': f'Espera {int(wait_time)} segundos antes de hacer otra verificación. Esto ayuda a evitar bloqueos del sistema de pago.'
                }), 429
        
        # Agregar delay aleatorio adicional (reducido también)
        additional_delay = random.uniform(1, 3)  # Reducido de 5-10 a 1-3 segundos
        time.sleep(additional_delay)
        
        # Obtener datos de la tarjeta
        data = request.json
        card_number = data.get('card_number', '').replace(' ', '').replace('-', '')
        exp_month = data.get('exp_month', '')
        exp_year = data.get('exp_year', '')
        cvv = data.get('cvv', '')
        
        # Validar datos de la tarjeta
        if not card_number or not exp_month or not exp_year or not cvv:
            return jsonify({
                'success': False,
                'error': 'Faltan datos de la tarjeta. Por favor, completa todos los campos.'
            }), 400
        
        # Limpiar número de tarjeta (eliminar espacios)
        card_number = re.sub(r'\s+', '', card_number)
        
        # Formatear año (asegurar formato correcto)
        if len(str(exp_year)) == 2:
            exp_year = '20' + str(exp_year)
        
        # Crear registro de historial
        check_record = CheckHistory(
            user_id=user.id,
            payment_method_id='',  # No hay payment_method_id en este modo
            status='pending',
            mode='charge'
        )
        db.session.add(check_record)
        db.session.commit()
        
        try:
            # Obtener user agent
            user_agent = request.headers.get('User-Agent', '')
            
            # Llamar a la función de verificación
            result = verify_stripe_charge(
                card_number=card_number,
                exp_month=str(exp_month).zfill(2),
                exp_year=str(exp_year),
                cvv=str(cvv),
                user_agent=user_agent
            )
            
            # Incrementar contador
            user.checks_today += 1
            
            # Actualizar registro de historial
            if result.get('success'):
                check_record.status = 'approved'
                details = result.get('details', {})
                card_details = details.get('card', {})
                check_record.card_last4 = card_details.get('last4', '')[-4:] if card_details.get('last4') else ''
                check_record.card_brand = card_details.get('brand', '')
                check_record.card_type = card_details.get('type', '')
                check_record.card_country = card_details.get('country', '')
            else:
                check_record.status = 'declined'
                check_record.error_code = result.get('status', 'declined')
            
            db.session.commit()
            
            # Obtener información del BIN para el país
            bin_info = result.get('details', {}).get('bin_info')
            if not bin_info:
                # Si no hay bin_info, intentar obtenerlo desde el número de tarjeta
                bin_number = card_number[:6] if len(card_number) >= 6 else ''
                if bin_number:
                    try:
                        bin_response = requests.get(
                            f"https://lookup.binlist.net/{bin_number}",
                            headers={'Accept-Version': '3'},
                            timeout=5
                        )
                        if bin_response.status_code == 200:
                            bin_info = bin_response.json()
                            if not bin_info.get('country'):
                                bin_info = None
                    except Exception:
                        bin_info = None
            
            # Preparar respuesta
            success = result.get('success', False)
            status = result.get('status', 'error')
            message = result.get('message', '')
            
            # Si no hay mensaje, generar uno basado en el status
            if not message or message.strip() == '':
                if success:
                    message = 'Tarjeta válida ✅'
                elif status == 'declined':
                    message = 'Tarjeta rechazada ❌'
                elif status == 'error':
                    message = 'Error al procesar la tarjeta ❌'
                else:
                    message = f'Error: {status}'
            
            response_data = {
                'success': success,
                'message': message,
                'status': status,
                'mode': 'charge',
                'checks_remaining': user.max_checks - user.checks_today,
                'details': {
                    'card': result.get('details', {}).get('card', {}),
                    'bin_info': bin_info
                }
            }
            
            # Si hay error, asegurarse de que esté en el campo 'error' también
            if not success:
                response_data['error'] = message
            
            return jsonify(response_data)
        
        except Exception as e:
            user.checks_today += 1
            if 'check_record' in locals() and check_record:
                check_record.status = 'error'
                check_record.error_code = 'unexpected_error'
            db.session.commit()
            
            error_msg = str(e) if e else 'Error desconocido'
            logger.error(f'Error en verify_charge: {error_msg}', exc_info=True)
            
            return jsonify({
                'success': False,
                'error': f'Error al procesar tarjeta: {error_msg}',
                'message': f'Error al procesar tarjeta: {error_msg}',
                'status': 'error',
                'checks_remaining': user.max_checks - user.checks_today
            }), 500
    
    except Exception as e:
        error_msg = str(e) if e else 'Error desconocido en el servidor'
        logger.error(f'Error en verify_charge (outer): {error_msg}', exc_info=True)
        return jsonify({
            'success': False,
            'error': f'Error al procesar la solicitud: {error_msg}',
            'message': f'Error al procesar la solicitud: {error_msg}',
            'status': 'error'
        }), 500

@app.route('/checker/verify_stripe_auth', methods=['POST'])
@rate_limit(max_requests=30, window_seconds=60)
@key_required
def checker_verify_stripe_auth():
    """Endpoint para verificar tarjetas usando Stripe Auth (charitywater.org)"""
    try:
        config = load_config()
        
        # Verificar modo mantenimiento
        if config.get('maintenance_mode', False):
            return jsonify({
                'success': False,
                'error': 'Sistema en mantenimiento'
            }), 503
        
        # Verificar si el gate stripe_auth está habilitado
        gates_config = get_gates_config()
        if not gates_config.get('stripe_auth', {}).get('enabled', True):
            return jsonify({
                'success': False,
                'error': '⚠️ Gate Stripe Auth está actualmente en mantenimiento.',
                'status': 'maintenance'
            }), 503
        
        # Obtener información del usuario
        user_key = session.get('user_key')
        user = User.query.filter_by(key=user_key).first()
        
        if not user:
            return jsonify({
                'success': False,
                'error': 'Usuario no encontrado'
            }), 404
        
        # Verificar límite diario
        today = date.today()
        if user.last_check_date != today:
            user.checks_today = 0
            user.last_check_date = today
            db.session.commit()
        
        if user.checks_today >= user.max_checks:
            return jsonify({
                'success': False,
                'error': f'Has alcanzado el límite de {user.max_checks} checks. Contacta al administrador.'
            }), 429
        
        # Obtener datos de la tarjeta
        data = request.json
        card_number = data.get('card_number', '').strip().replace(' ', '').replace('-', '')
        exp_month = data.get('exp_month', '').strip()
        exp_year = data.get('exp_year', '').strip()
        cvv = data.get('cvv', '').strip()
        
        if not all([card_number, exp_month, exp_year, cvv]):
            return jsonify({
                'success': False,
                'error': 'Datos de tarjeta incompletos'
            }), 400
        
        # Formatear año (asegurar formato correcto)
        if len(str(exp_year)) == 2:
            exp_year = '20' + str(exp_year)
        
        # Crear registro de historial
        check_record = CheckHistory(
            user_id=user.id,
            payment_method_id=None,
            status='pending',
            mode='stripe_auth'
        )
        db.session.add(check_record)
        db.session.commit()
        
        try:
            # Obtener user agent
            user_agent = request.headers.get('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            
            # Llamar a la función de verificación
            result = verify_stripe_auth(
                card_number=card_number,
                exp_month=str(exp_month).zfill(2),
                exp_year=str(exp_year),
                cvv=str(cvv),
                user_agent=user_agent
            )
            
            # Incrementar contador
            user.checks_today += 1
            
            # Actualizar historial según el resultado
            if result.get('success'):
                check_record.status = 'approved'
                details = result.get('details', {})
                card_details = details.get('card', {})
                check_record.card_last4 = card_number[-4:] if len(card_number) >= 4 else ''
                check_record.card_brand = card_details.get('brand', '')
                check_record.card_type = card_details.get('type', '')
                check_record.card_country = card_details.get('country', '')
            else:
                # Distinguir entre error de merchant y error de tarjeta
                error_code = result.get('details', {}).get('error_code', result['status'])
                if error_code in ['merchant_account_error', 'merchant_restriction']:
                    check_record.status = 'error'
                    # No incrementar contador si es error del merchant
                    user.checks_today -= 1
                else:
                    check_record.status = 'declined'
                check_record.error_code = error_code
            
            db.session.commit()
            
            # Obtener información del BIN
            bin_info = result.get('details', {}).get('bin_info')
            if not bin_info:
                # Si no hay bin_info, intentar obtenerlo desde el número de tarjeta
                bin_number = card_number[:6] if len(card_number) >= 6 else ''
                if bin_number:
                    try:
                        bin_response = requests.get(
                            f"https://lookup.binlist.net/{bin_number}",
                            headers={'Accept-Version': '3'},
                            timeout=5
                        )
                        if bin_response.status_code == 200:
                            bin_info = bin_response.json()
                            if not bin_info.get('country'):
                                bin_info = None
                    except Exception:
                        bin_info = None
            
            # Preparar respuesta
            success = result.get('success', False)
            status = result.get('status', 'error')
            message = result.get('message', '')
            
            # Si no hay mensaje, generar uno basado en el status
            if not message or message.strip() == '':
                if success:
                    message = 'Tarjeta válida ✅ (Auth - Sin Cargo)'
                elif status == 'declined':
                    message = 'Tarjeta rechazada ❌'
                elif status == 'error':
                    message = 'Error al procesar la tarjeta'
                else:
                    message = f'Error: {status}'
            
            response_data = {
                'success': success,
                'message': message,
                'status': status,
                'mode': 'stripe_auth',
                'checks_remaining': user.max_checks - user.checks_today,
                'details': {
                    'card': result.get('details', {}).get('card', {}),
                    'bin_info': bin_info
                }
            }
            
            # Si hay error, asegurarse de que esté en el campo 'error' también
            if not success:
                response_data['error'] = message
                # Si es error de merchant, retornar 503 en lugar de 400
                if status == 'error':
                    return jsonify(response_data), 503
            
            return jsonify(response_data)
        
        except Exception as e:
            user.checks_today += 1
            if 'check_record' in locals() and check_record:
                check_record.status = 'error'
                check_record.error_code = 'unexpected_error'
            db.session.commit()
            
            error_msg = str(e) if e else 'Error desconocido'
            logger.error(f'Error en verify_stripe_auth: {error_msg}', exc_info=True)
            
            return jsonify({
                'success': False,
                'error': f'Error al procesar tarjeta: {error_msg}',
                'message': f'Error al procesar tarjeta: {error_msg}',
                'status': 'error',
                'mode': 'stripe_auth',
                'checks_remaining': user.max_checks - user.checks_today
            }), 500
    
    except Exception as e:
        error_msg = str(e) if e else 'Error desconocido en el servidor'
        logger.error(f'Error general en verify_stripe_auth: {error_msg}', exc_info=True)
        return jsonify({
            'success': False,
            'error': f'Error al procesar la solicitud: {error_msg}',
            'message': f'Error al procesar la solicitud: {error_msg}',
            'status': 'error'
        }), 500

@app.route('/checker/verify_braintree', methods=['POST'])
@rate_limit(max_requests=10, window_seconds=60)
@key_required
def checker_verify_braintree():
    """Endpoint para verificar tarjetas usando Braintree (3D Secure)"""
    try:
        config = load_config()
        
        # Verificar modo mantenimiento
        if config.get('maintenance_mode', False):
            return jsonify({
                'success': False,
                'error': 'Sistema en mantenimiento'
            }), 503
        
        # Verificar si el gate Braintree está habilitado
        gates_config = get_gates_config()
        if not gates_config.get('braintree', {}).get('enabled', False):
            return jsonify({
                'success': False,
                'error': '⚠️ Gate Braintree está actualmente en mantenimiento.',
                'status': 'maintenance'
            }), 503
        
        # Obtener información del usuario
        user_key = session.get('user_key')
        user = User.query.filter_by(key=user_key).first()
        
        if not user:
            return jsonify({
                'success': False,
                'error': 'Usuario no encontrado'
            }), 404
        
        # Verificar límite diario
        today = date.today()
        if user.last_check_date != today:
            user.checks_today = 0
            user.last_check_date = today
            db.session.commit()
        
        if user.checks_today >= user.max_checks:
            return jsonify({
                'success': False,
                'error': f'Has alcanzado el límite de {user.max_checks} checks.'
            }), 429
        
        # Obtener datos de la tarjeta
        data = request.json
        card_number = data.get('card_number', '').strip().replace(' ', '').replace('-', '')
        exp_month = data.get('exp_month', '').strip()
        exp_year = data.get('exp_year', '').strip()
        cvv = data.get('cvv', '').strip()
        
        if not all([card_number, exp_month, exp_year, cvv]):
            return jsonify({
                'success': False,
                'error': 'Datos de tarjeta incompletos'
            }), 400
        
        # Crear registro de historial
        check_record = CheckHistory(
            user_id=user.id,
            payment_method_id=None,
            status='pending',
            mode='braintree'
        )
        db.session.add(check_record)
        db.session.commit()
        
        try:
            # Usar la función del módulo braintree3d
            user_agent = request.headers.get('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            result = verify_braintree_card(card_number, exp_month, exp_year, cvv, user_agent)
            
            # Incrementar contador
            user.checks_today += 1
            
            # Actualizar historial según el resultado
            if result['success']:
                check_record.status = 'approved'
                card_details = result.get('details', {}).get('card', {})
                check_record.card_last4 = card_details.get('last4', '')
                check_record.card_brand = card_details.get('brand', '')
                check_record.card_type = card_details.get('type', 'CREDIT')
                db.session.commit()
                
                return jsonify({
                    'success': True,
                    'message': f'✅ {result["message"]}',
                    'status': 'approved',
                    'mode': 'braintree',
                    'checks_remaining': user.max_checks - user.checks_today,
                    'details': result.get('details', {})
                })
            else:
                check_record.status = 'declined' if result['status'] == 'declined' else 'error'
                check_record.error_code = result.get('details', {}).get('error_code', result['status'])
                db.session.commit()
                
                return jsonify({
                    'success': False,
                    'error': f'❌ {result["message"]}',
                    'status': result['status'],
                    'mode': 'braintree',
                    'checks_remaining': user.max_checks - user.checks_today,
                    'details': result.get('details', {})
                }), 400
        
        except Exception as e:
            error_msg = str(e) if e else 'Error desconocido'
            logger.error(f"Error en verificación Braintree: {error_msg}", exc_info=True)
            check_record.status = 'error'
            check_record.error_code = 'unexpected_error'
            user.checks_today += 1
            db.session.commit()
            
            return jsonify({
                'success': False,
                'error': f'Error al procesar tarjeta: {error_msg}',
                'message': f'Error al procesar tarjeta: {error_msg}',
                'status': 'error',
                'mode': 'braintree',
                'checks_remaining': user.max_checks - user.checks_today,
            }), 500
    
    except Exception as e:
        error_msg = str(e) if e else 'Error desconocido en el servidor'
        logger.error(f"Error general en verify_braintree: {error_msg}", exc_info=True)
        return jsonify({
            'success': False,
            'error': f'Error al procesar la solicitud: {error_msg}',
            'message': f'Error al procesar la solicitud: {error_msg}',
            'status': 'error'
        }), 500

if __name__ == '__main__':
    # Obtener configuración desde la base de datos
    with app.app_context():
        admin_pass = get_config('admin_password', 'admin123')
    
    print("🎤 Iniciando Snoop Dogg Checker Beta...")
    print(f"📊 Admin Panel: http://0.0.0.0:5000/admin/login")
    print(f"🔍 Checker: http://0.0.0.0:5000/checker/auth")
    print(f"🔑 Password Admin: {admin_pass}")
    print("="*50)
    
    # En desarrollo local
    debug_mode = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    port = int(os.environ.get('PORT', 5000))
    
    app.run(debug=debug_mode, host='0.0.0.0', port=port)
