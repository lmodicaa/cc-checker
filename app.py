from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import stripe
from stripe._error import CardError, AuthenticationError, StripeError
import os
import requests
import secrets
import hashlib
import logging
from datetime import datetime, timedelta, date
from functools import wraps
from models import db, Config, User, CheckHistory

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
        
        # Inicializar configuración por defecto si no existe
        if Config.query.count() == 0:
            print("📝 Inicializando configuración por defecto...")
            default_configs = [
                ('admin_password', 'Mon11$$99'),
                ('stripe_pk', ''),
                ('stripe_sk', ''),
                ('daily_limit', '50'),
                ('maintenance_mode', 'false')
            ]
            for key, value in default_configs:
                config = Config(key=key, value=value)
                db.session.add(config)
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

# Rate limiting simple (en memoria)
from collections import defaultdict
import time

# Almacén de intentos por IP
rate_limit_storage = defaultdict(list)

def rate_limit(max_requests=10, window_seconds=60):
    """Decorador para rate limiting por IP"""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            ip = request.remote_addr
            now = time.time()
            
            # Limpiar intentos antiguos
            rate_limit_storage[ip] = [req_time for req_time in rate_limit_storage[ip] 
                                      if now - req_time < window_seconds]
            
            # Verificar límite
            if len(rate_limit_storage[ip]) >= max_requests:
                logger.warning(f"Rate limit exceeded for IP: {ip}")
                return jsonify({
                    'success': False,
                    'error': 'Demasiadas solicitudes. Intenta de nuevo en un momento.'
                }), 429
            
            # Agregar intento actual
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
    ip = request.remote_addr
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
    return config_dict

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
        user_key = session.get('user_key')
        if not user_key:
            return redirect(url_for('checker_auth'))
        
        # Verificar que la key sigue siendo válida
        user = User.query.filter_by(key=user_key).first()
        if not user:
            session.clear()
            return redirect(url_for('checker_auth'))
        
        if not user.active:
            session.clear()
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
                error_details['message'] = 'Tarjeta rechazada - Fondos insuficientes'
            elif 'lost_card' in error_code:
                error_details['message'] = 'Tarjeta rechazada - Tarjeta reportada como perdida'
            elif 'stolen_card' in error_code:
                error_details['message'] = 'Tarjeta rechazada - Tarjeta reportada como robada'
            elif 'expired_card' in error_code:
                error_details['message'] = 'Tarjeta rechazada - Tarjeta expirada'
        elif 'incorrect_cvc' in error_code.lower():
            error_details['type'] = 'cvv_error'
            error_details['message'] = 'CVV incorrecto'
        elif 'incorrect_number' in error_code.lower():
            error_details['type'] = 'card_number_error'
            error_details['message'] = 'Número de tarjeta inválido'
    
    return error_details

# ==================== RUTAS ADMIN ====================

@app.route('/admin/login', methods=['GET', 'POST'])
@rate_limit(max_requests=5, window_seconds=300)  # 5 intentos cada 5 minutos
def admin_login():
    if request.method == 'POST':
        password = request.json.get('password', '').strip()
        admin_password = get_config('admin_password', 'admin123')
        
        if password == admin_password:
            session['is_admin'] = True
            log_security_event('ADMIN_LOGIN_SUCCESS', 'Admin login successful')
            logger.info(f"Admin login successful from IP: {request.remote_addr}")
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
    
    # Contar estadísticas
    total_keys = User.query.count()
    active_keys = User.query.filter_by(active=True).count()
    
    return jsonify({
        'config': config,
        'stats': {
            'total_keys': total_keys,
            'active_keys': active_keys
        }
    })

@app.route('/admin/update_config', methods=['POST'])
@admin_required
def update_config():
    data = request.json
    
    # Actualizar configuración
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
        set_config('maintenance_mode', data['maintenance_mode'])
    
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
@rate_limit(max_requests=10, window_seconds=60)  # 10 intentos por minuto
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
        ip_address = request.remote_addr
        current_fingerprint = get_device_fingerprint(user_agent, ip_address)
        
        # Si la key ya tiene un dispositivo registrado
        if user.device_fingerprint:
            if user.device_fingerprint != current_fingerprint:
                log_security_event('DEVICE_MISMATCH', f'User: {user.name}, Expected: {user.device_fingerprint[:20]}, Got: {current_fingerprint[:20]}', user_id=user.id)
                return jsonify({
                    'success': False,
                    'error': 'Esta key ya está siendo usada en otro dispositivo/IP'
                }), 403
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
    config = load_config()
    
    # Verificar modo mantenimiento
    if config.get('maintenance_mode', False):
        return render_template('maintenance.html')
    
    return render_template('checker.html')

@app.route('/checker/get_config', methods=['GET'])
@key_required
def checker_get_config():
    """Endpoint para que el checker obtenga la configuración de Stripe PK"""
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
        
        return jsonify({
            'success': True,
            'stripe_pk': get_config('stripe_pk', ''),
            'checks_remaining': checks_remaining,
            'max_checks': user.max_checks
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
    """Endpoint para verificar tarjetas en modo Auth (solo para usuarios con key)"""
    try:
        config = load_config()
        
        # Verificar modo mantenimiento
        if config.get('maintenance_mode', False):
            return jsonify({
                'success': False,
                'error': 'Sistema en mantenimiento'
            }), 503
        
        # Configurar Stripe API key
        stripe.api_key = config['stripe_sk']
        
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
            # Resetear contador si es un nuevo día
            user.checks_today = 0
            user.last_check_date = today
            db.session.commit()
        
        # Usar el límite personalizado de cada usuario
        if user.checks_today >= user.max_checks:
            return jsonify({
                'success': False,
                'error': f'Límite alcanzado ({user.max_checks} checks por key)'
            }), 429
        
        # Obtener datos de la tarjeta
        data = request.json
        payment_method_id = data.get('payment_method_id')
        
        if not payment_method_id:
            return jsonify({
                'success': False,
                'error': 'No se proporcionó payment_method_id'
            }), 400
        
        # Crear registro de historial ANTES de intentar la verificación
        # Así siempre existirá para actualizar en caso de error
        check_record = CheckHistory(
            user_id=user.id,
            payment_method_id=payment_method_id,
            status='pending',
            mode='auth'
        )
        db.session.add(check_record)
        db.session.commit()
        
        try:
            # Crear SetupIntent (Auth mode)
            setup_intent = stripe.SetupIntent.create(
                payment_method=payment_method_id,
                payment_method_types=['card']
            )
            
            if not setup_intent or not setup_intent.id:
                check_record.status = 'error'
                check_record.error_code = 'setup_intent_create_failed'
                user.checks_today += 1
                db.session.commit()
                return jsonify({
                    'success': False,
                    'error': 'Error al crear SetupIntent',
                    'status': 'error'
                }), 400
            
            setup_intent = stripe.SetupIntent.confirm(
                setup_intent.id,
                payment_method=payment_method_id,
            )
            
            if not setup_intent:
                check_record.status = 'error'
                check_record.error_code = 'setup_intent_confirm_failed'
                user.checks_today += 1
                db.session.commit()
                return jsonify({
                    'success': False,
                    'error': 'Error al confirmar SetupIntent',
                    'status': 'error'
                }), 400
            
            # Incrementar contador solo después de confirmar
            user.checks_today += 1
            db.session.commit()
            
            # Obtener información del PaymentMethod
            payment_method = stripe.PaymentMethod.retrieve(payment_method_id)
            
            # Validar que el payment_method existe
            if not payment_method:
                return jsonify({
                    'success': False,
                    'error': 'No se pudo obtener información del método de pago',
                    'status': 'error'
                }), 400
            
            # Obtener información de la tarjeta de forma segura
            card_info = {}
            if hasattr(payment_method, 'card') and payment_method.card:
                card_info = payment_method.card
            
            # Obtener información del BIN para el país
            bin_info = None
            bin_number = None
            
            if card_info:
                # Intentar obtener el BIN
                for attr in ['bin', 'iin', 'issuer_identification_number']:
                    if hasattr(card_info, attr):
                        bin_number = getattr(card_info, attr, None)
                        if bin_number:
                            break
                
                if not bin_number and isinstance(card_info, dict):
                    bin_number = card_info.get('bin') or card_info.get('iin')
                
                if bin_number:
                    bin_number = str(bin_number).strip()
                
                # Consultar binlist.net solo para obtener info del país
                if bin_number and len(bin_number) >= 6:
                    try:
                        bin_lookup = bin_number[:6]
                        bin_response = requests.get(
                            f"https://lookup.binlist.net/{bin_lookup}",
                            headers={'Accept-Version': '3'},
                            timeout=5
                        )
                        if bin_response.status_code == 200:
                            bin_info = bin_response.json()
                            if not bin_info.get('country'):
                                bin_info = None
                    except Exception:
                        bin_info = None
                
                # Si no hay BIN, construir info básica del país desde Stripe
                if not bin_info and card_info.get('country'):
                    bin_info = {
                        'country': {
                            'alpha2': card_info.get('country'),
                            'name': None
                        }
                    }
            
            if setup_intent.status == 'succeeded':
                # Actualizar historial como aprobado
                check_record.status = 'approved'
                check_record.card_last4 = card_info.get('last4')
                check_record.card_brand = card_info.get('brand')
                check_record.card_type = card_info.get('funding')
                check_record.card_country = card_info.get('country')
                db.session.commit()
                
                return jsonify({
                    'success': True,
                    'message': 'Tarjeta válida (Auth) ✅',
                    'status': 'approved',
                    'mode': 'auth',
                    'checks_remaining': user.max_checks - user.checks_today,
                    'details': {
                        'setup_intent_id': setup_intent.id,
                        'status': setup_intent.status,
                        'card': {
                            'last4': card_info.get('last4', ''),
                            'brand': card_info.get('brand', '').upper() if card_info.get('brand') else '',
                            'type': card_info.get('funding', '').upper() if card_info.get('funding') else '',
                            'exp_month': card_info.get('exp_month', ''),
                            'exp_year': card_info.get('exp_year', ''),
                            'country': card_info.get('country', '').upper() if card_info.get('country') else '',
                            'bin': str(bin_number) if bin_number else '',
                            'issuer': card_info.get('issuer', ''),
                            'networks': card_info.get('networks', {}),
                        },
                        'bin_info': bin_info,
                        'stripe_bin': str(bin_number) if bin_number else ''
                    }
                })
            elif setup_intent.status == 'requires_action':
                # Actualizar historial como aprobado (requiere 3DS)
                check_record.status = 'approved'
                check_record.card_last4 = card_info.get('last4')
                check_record.card_brand = card_info.get('brand')
                check_record.card_type = card_info.get('funding')
                check_record.card_country = card_info.get('country')
                db.session.commit()
                
                return jsonify({
                    'success': True,
                    'message': 'Tarjeta válida (Auth) ✅ - Requiere 3D Secure',
                    'status': 'approved',
                    'mode': 'auth',
                    'checks_remaining': user.max_checks - user.checks_today,
                    'details': {
                        'setup_intent_id': setup_intent.id,
                        'status': setup_intent.status,
                        'requires_3ds': True,
                        'card': {
                            'last4': card_info.get('last4', ''),
                            'brand': card_info.get('brand', '').upper() if card_info.get('brand') else '',
                            'type': card_info.get('funding', '').upper() if card_info.get('funding') else '',
                            'exp_month': card_info.get('exp_month', ''),
                            'exp_year': card_info.get('exp_year', ''),
                            'country': card_info.get('country', '').upper() if card_info.get('country') else '',
                            'bin': str(bin_number) if bin_number else '',
                            'issuer': card_info.get('issuer', ''),
                            'networks': card_info.get('networks', {}),
                        },
                        'bin_info': bin_info,
                        'stripe_bin': str(bin_number) if bin_number else ''
                    }
                })
            else:
                # Actualizar historial como error
                check_record.status = 'error'
                check_record.error_code = f'unexpected_status_{setup_intent.status}'
                db.session.commit()
                
                return jsonify({
                    'success': False,
                    'error': f'Estado inesperado: {setup_intent.status}',
                    'status': 'error',
                    'details': {'status': setup_intent.status}
                })
        
        except CardError as e:
            # Incrementar contador incluso en errores
            user.checks_today += 1
            
            # Actualizar historial como rechazado
            check_record.status = 'declined'
            check_record.error_code = getattr(e, 'code', None)
            db.session.commit()
            
            error_details = parse_error_details(e)
            return jsonify({
                'success': False,
                'error': error_details['message'],
                'status': 'declined',
                'mode': 'auth',
                'checks_remaining': user.max_checks - user.checks_today,
                'details': error_details
            })
        
    except AuthenticationError as e:
        # Si el check_record existe, actualizarlo
        if 'check_record' in locals() and check_record:
            check_record.status = 'error'
            check_record.error_code = 'authentication_error'
            db.session.commit()
        
        return jsonify({
            'success': False,
            'error': f'Error de autenticación con Stripe: {str(e)}',
            'status': 'auth_error'
        }), 401
    
    except StripeError as e:
        error_details = parse_error_details(e)
        
        # Si el check_record existe, actualizarlo
        if 'check_record' in locals() and check_record:
            check_record.status = 'error'
            check_record.error_code = getattr(e, 'code', 'stripe_error')
            db.session.commit()
        
        return jsonify({
            'success': False,
            'error': error_details['message'],
            'status': 'error',
            'details': error_details
        }), 400
    
    except Exception as e:
        # Si el check_record existe, actualizarlo
        if 'check_record' in locals() and check_record:
            check_record.status = 'error'
            check_record.error_code = 'unexpected_error'
            db.session.commit()
        
        return jsonify({
            'success': False,
            'error': f'Error inesperado: {str(e)}',
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
