import boto3
import hashlib
import json
import jwt
import os
from datetime import datetime, timedelta

# Hashear contraseña
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Generar token JWT
def generate_jwt_token(user_data):
    JWT_SECRET = os.environ.get('JWT_SECRET', 'utec')
    
    # Payload del token
    payload = {
        'user_id': user_data.get('user_id'),
        'email': user_data.get('email'),
        'user_type': user_data.get('user_type'),
        'staff_tier': user_data.get('staff_tier'),
        'permissions': user_data.get('permissions', []),
        'exp': datetime.utcnow() + timedelta(hours=24),  # Expira en 24 horas
        'iat': datetime.utcnow(),  # Fecha de emisión
        'frontend_type': user_data.get('frontend_type', 'client')
    }
    
    # Generar token JWT
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    
    return token, payload['exp']

# Verificar token JWT
def verify_jwt_token(token):
    try:
        JWT_SECRET = os.environ.get('JWT_SECRET', 'utec')
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        print("Token expirado")
        return None
    except jwt.InvalidTokenError:
        print("Token inválido")
        return None

# Función para determinar redirección después del login
def get_redirect_path(user_type, frontend_type):
    """
    Determina a dónde redirigir después del login exitoso
    """
    if user_type == 'staff':
        return '/admin/dashboard'
    else:
        if frontend_type == 'client':
            return '/dashboard'
        else:
            return '/'

# Headers CORS para todas las respuestas
CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS, GET',
    'Access-Control-Allow-Headers': 'Content-Type, X-Amz-Date, Authorization, X-Api-Key, X-Amz-Security-Token, Accept',
    'Content-Type': 'application/json'
}

# Función principal del Lambda de Login
def lambda_handler(event, context):
    try:
        print("Login event received:", json.dumps(event, indent=2))
        
        # ✅ CORRECCIÓN: API Gateway envía datos en event['body'] como string
        if 'body' in event:
            if isinstance(event['body'], str):
                body = json.loads(event['body'])
            else:
                body = event['body']
        else:
            body = event

        email = body.get('email', '').lower().strip()
        password = body.get('password')
        frontend_type = body.get('frontend_type', 'client')  # 'client' o 'staff'
        
        # Validación 1: Campos obligatorios
        if not email or not password:
            return {
                'statusCode': 400,
                'headers': CORS_HEADERS,
                'body': json.dumps({
                    'error': 'Campos obligatorios faltantes: email y password son requeridos'
                })
            }
        
        # Validación 2: Frontend type
        if frontend_type not in ['client', 'staff']:
            return {
                'statusCode': 400,
                'headers': CORS_HEADERS,
                'body': json.dumps({
                    'error': 'frontend_type debe ser "client" o "staff"'
                })
            }
        
        dynamodb = boto3.resource('dynamodb')
        t_usuarios = dynamodb.Table('t_usuarios')
        
        # Buscar usuario por email
        try:
            response = t_usuarios.get_item(Key={'email': email})
            if 'Item' not in response:
                # No revelar si el usuario existe o no por seguridad
                return {
                    'statusCode': 401,
                    'headers': CORS_HEADERS,
                    'body': json.dumps({
                        'error': 'Credenciales inválidas'
                    })
                }
            
            user = response['Item']
            
        except Exception as e:
            print(f"Error fetching user: {str(e)}")
            return {
                'statusCode': 500,
                'headers': CORS_HEADERS,
                'body': json.dumps({
                    'error': 'Error interno del servidor'
                })
            }
        
        # Verificar contraseña
        hashed_input = hash_password(password)
        if hashed_input != user.get('password'):
            return {
                'statusCode': 401,
                'headers': CORS_HEADERS,
                'body': json.dumps({
                    'error': 'Credenciales inválidas'
                })
            }
        
        # Verificar que el usuario esté activo
        if not user.get('is_active', True):
            return {
                'statusCode': 403,
                'headers': CORS_HEADERS,
                'body': json.dumps({
                    'error': 'Cuenta desactivada. Contacta al administrador.'
                })
            }
        
        user_type = user.get('user_type', 'cliente')
        
        if frontend_type == 'staff':
            # Login desde staff frontend - solo permitir staff
            if user_type != 'staff':
                return {
                    'statusCode': 403,
                    'headers': CORS_HEADERS,
                    'body': json.dumps({
                        'error': 'Acceso denegado. El portal staff es solo para personal autorizado.'
                    })
                }
            
            # Verificar que staff tenga tier asignado
            if not user.get('staff_tier'):
                return {
                    'statusCode': 403,
                    'headers': CORS_HEADERS,
                    'body': json.dumps({
                        'error': 'Cuenta de staff incompleta. Contacta al administrador.'
                    })
                }
                
        elif frontend_type == 'client':
            # Login desde client frontend - solo permitir clientes
            if user_type == 'staff':
                return {
                    'statusCode': 403,
                    'headers': CORS_HEADERS,
                    'body': json.dumps({
                        'error': 'Acceso denegado. El personal debe usar el portal staff.'
                    })
                }
            
            # Verificar email para clientes
            if not user.get('is_verified', False):
                return {
                    'statusCode': 403,
                    'headers': CORS_HEADERS,
                    'body': json.dumps({
                        'error': 'Por favor verifica tu email antes de iniciar sesión.',
                        'requires_verification': True
                    })
                }
        
        current_time = datetime.utcnow().isoformat()
        
        try:
            t_usuarios.update_item(
                Key={'email': email},
                UpdateExpression='SET last_login = :login_time, updated_at = :update_time',
                ExpressionAttributeValues={
                    ':login_time': current_time,
                    ':update_time': current_time
                }
            )
        except Exception as e:
            print(f"Error updating last login: {str(e)}")
            
        ## GENERAR TOKEN JWT

        # Preparar datos del usuario para el token
        user_token_data = {
            'user_id': user.get('user_id'),
            'email': user.get('email'),
            'user_type': user_type,
            'staff_tier': user.get('staff_tier'),
            'permissions': user.get('permissions', []),
            'frontend_type': frontend_type
        }
        
        # Generar token JWT
        token, expires_at = generate_jwt_token(user_token_data)

        # Datos del usuario para la respuesta
        user_data = {
            'user_id': user.get('user_id'),
            'email': user.get('email'),
            'name': user.get('name'),
            'user_type': user_type,
            'is_active': user.get('is_active', True),
            'last_login': current_time
        }
        
        # Agregar información específica por tipo de usuario
        if user_type == 'staff':
            user_data['staff_tier'] = user.get('staff_tier')
            user_data['permissions'] = user.get('permissions', [])
            user_data['is_verified'] = user.get('is_verified', True)
        else:
            user_data['is_verified'] = user.get('is_verified', False)
        
        # Determinar redirección
        redirect_path = get_redirect_path(user_type, frontend_type)
        user_data['redirect_to'] = redirect_path
        
        response_data = {
            'message': 'Login exitoso',
            'user': user_data,
            'token': token,
            'token_expires': expires_at.isoformat(),
            'session': {
                'logged_in_at': current_time,
                'frontend_type': frontend_type
            },
            'cookie_instructions': {
                'name': 'auth_token',
                'value': token,
                'expires': expires_at.isoformat(),
                'httpOnly': True,
                'secure': True,
                'sameSite': 'Strict',
                'path': '/'
            }
        }
        
        return {
            'statusCode': 200,
            'headers': CORS_HEADERS,
            'body': json.dumps(response_data)
        }

    except Exception as e:
        print("Exception in login:", str(e))
        error_response = {
            'error': 'Error interno del servidor',
            'code': 'INTERNAL_ERROR'
        }
        
        return {
            'statusCode': 500,
            'headers': CORS_HEADERS,
            'body': json.dumps(error_response)
        }