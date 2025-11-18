import boto3
import hashlib
import uuid
import json
from datetime import datetime, timedelta

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_access_token(user_data):

    dynamodb = boto3.resource('dynamodb')
    table_tokens = dynamodb.Table('t_tokens_acceso')
    
    # Generar token único
    token = str(uuid.uuid4())

    # Calcular fecha de expiración
    expires_at = datetime.now() + timedelta(minutes=120)
    
    # Crear registro del token
    ## Tal vez borrar campos
    token_record = {
        'token': token,
        'user_id': user_data.get('user_id'),
        'email': user_data.get('email'),
        'user_type': user_data.get('user_type'),
        'staff_tier': user_data.get('staff_tier'),
        'permissions': user_data.get('permissions', []),
        'expires_at': expires_at.strftime('%Y-%m-%d %H:%M:%S'),
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'is_active': True,
        'frontend_type': user_data.get('frontend_type', 'client')
    }
    table_tokens.put_item(Item=token_record)
    return token, expires_at

# Función para determinar redirección después del login
def get_redirect_path(user_type, frontend_type):
    ## A dónde ir después del login
    if user_type == 'staff':
        return '/admin/dashboard'
    else:
        if frontend_type == 'client':
            return '/dashboard'
        else:
            return '/'

# Función principal del Lambda de Login
def lambda_handler(event, context):
    try:
        email = event.get('email', '').lower().strip()
        password = event.get('password')
        frontend_type = event.get('frontend_type')  # 'client' o 'staff'

        # Validación 1: Campos obligatorios
        if not email or not password:
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'error': 'Campos obligatorios faltantes: email y password son requeridos'
                })
            }
        
        # Validación 2: Frontend type
        if not frontend_type or frontend_type not in ['client', 'staff']:
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'error': 'frontend_type es requerido y debe ser "client" o "staff"'
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
                    'body': json.dumps({
                        'error': 'Credenciales inválidas'
                    })
                }
            
            user = response['Item']
            
        except Exception as e:
            print(f"Error fetching user: {str(e)}")
            return {
                'statusCode': 500,
                'body': json.dumps({
                    'error': 'Error interno del servidor'
                })
            }
        
        # Verificar contraseña
        hashed_input = hash_password(password)
        if hashed_input != user.get('password'):
            return {
                'statusCode': 401,
                'body': json.dumps({
                    'error': 'Credenciales inválidas'
                })
            }
        
        # Verificar que el usuario esté activo
        if not user.get('is_active', True):
            return {
                'statusCode': 403,
                'body': json.dumps({
                    'error': 'Cuenta desactivada. Contacta al administrador.'
                })
            }
        
        ## Validación staff o cliente
        
        user_type = user.get('user_type', 'cliente')
        
        if frontend_type == 'staff':
            # Login desde staff frontend - solo permitir staff
            if user_type != 'staff':
                return {
                    'statusCode': 403,
                    'body': json.dumps({
                        'error': 'Acceso denegado. El portal staff es solo para personal autorizado.'
                    })
                }
            
            # Verificar que staff tenga tier asignado
            if not user.get('staff_tier'):
                return {
                    'statusCode': 403,
                    'body': json.dumps({
                        'error': 'Cuenta de staff incompleta. Contacta al administrador.'
                    })
                }
                
        elif frontend_type == 'client':
            # Login desde client frontend - solo permitir clientes
            if user_type == 'staff':
                return {
                    'statusCode': 403,
                    'body': json.dumps({
                        'error': 'Acceso denegado. El personal debe usar el portal staff.'
                    })
                }
            
            # Verificar email para clientes
            ## Comentar si no podemos validar por email
            if not user.get('is_verified', False):
                return {
                    'statusCode': 403,
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
        
        ## GENERAR TOKEN
        
        # Preparar datos del usuario para el token
        user_token_data = {
            'user_id': user.get('user_id'),
            'email': user.get('email'),
            'user_type': user_type,
            'staff_tier': user.get('staff_tier'),
            'permissions': user.get('permissions', []),
            'frontend_type': frontend_type
        }
        
        # Generar token
        token, expires_at = generate_access_token(user_token_data)

        # Datos del usuario para la respuesta (sin información sensible)
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
            'token_expires': expires_at.strftime('%Y-%m-%d %H:%M:%S'),
            'session': {
                'logged_in_at': current_time,
                'frontend_type': frontend_type
            },
            'cookie_instructions': {
                'name': 'auth_token',
                'value': token,
                'expires': expires_at.strftime('%Y-%m-%dT%H:%M:%S.000Z'),
                'httpOnly': True,
                'secure': True,
                'sameSite': 'Strict',
                'path': '/'
            }
        }
        
        return {
            'statusCode': 200,
            'body': response_data
        }

    except Exception as e:
        print("Exception in login:", str(e))
        error_response = {
            'error': 'Error interno del servidor',
            'code': 'INTERNAL_ERROR'
        }
        
        return {
            'statusCode': 500,
            'body': error_response
        }
