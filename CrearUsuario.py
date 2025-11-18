import boto3
import hashlib
import uuid
from datetime import datetime
import json

# Hashear contraseña
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Validar y asignar tier de staff
def validate_staff_tier(tier):
    valid_tiers = ['basic', 'gerente']
    if tier not in valid_tiers:
        raise ValueError(f"Tier inválido. Debe ser uno de: {valid_tiers}")
    return tier

# Validar código de invitación para  staff
def validate_invitation_code(code):
    if not code:
        return False
        
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('t_invitation_codes')
    
    try:
        response = table.get_item(Key={'code': code})
        if 'Item' in response:
            item = response['Item']
            
            # Verificar que esté activo y no haya expirado
            if (item.get('is_active', False) and 
                datetime.fromisoformat(item['expires_at']) > datetime.utcnow() and
                item.get('used_count', 0) < item.get('max_uses', 1)):
                
                # Incrementar contador de usos
                table.update_item(
                    Key={'code': code},
                    UpdateExpression='SET used_count = used_count + :inc',
                    ExpressionAttributeValues={':inc': 1}
                )
                return True
        return False
    except Exception as e:
        print(f"Error validating invitation code: {str(e)}")
        return False

# Asignar permisos basados en el tier de staff
def get_staff_permissions(tier):

    permissions = {
        'basic': [
            'view_products',
            'view_orders', 
            'update_order_status',
            'view_customers',
            'manage_own_profile'
        ],
        'gerente': [
            'view_products',
            'view_orders',
            'update_order_status', 
            'view_customers',
            'manage_products',
            'manage_orders',
            'manage_staff_basic',
            'view_reports',
            'manage_inventory',
            'generate_invitation_codes',
            'manage_all_profiles'
        ]
    }
    return permissions.get(tier, [])

# Función principal del Lambda
def lambda_handler(event, context):
    """
    Maneja el registro de usuarios para ambos frontends
    """
    try:
        password = event.get('password')
        name = event.get('name')
        email = event.get('email', '').lower().strip() 
        phone = event.get('phone')
        gender = event.get('gender')
        user_type = event.get('user_type', 'cliente')  # Default a cliente
        staff_tier = event.get('staff_tier')
        invitation_code = event.get('invitation_code')
        frontend_type = event.get('frontend_type')  # Identificar frontend

        # Validación 1: Campos obligatorios
        if not email or not password:
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'error': 'Campos obligatorios faltantes: email y password son requeridos'
                })
            }
        
        # Validación 2: Restricciones por tipo de frontend
        if frontend_type == 'staff':
            # Desde staff frontend, solo permitir registro de staff
            if user_type != 'staff':
                return {
                    'statusCode': 403,
                    'body': json.dumps({
                        'error': 'Acceso denegado. El portal staff es solo para registro de personal'
                    })
                }
            
            # Validar código de invitación para staff
            if not validate_invitation_code(invitation_code):
                return {
                    'statusCode': 403,
                    'body': json.dumps({
                        'error': 'Código de invitación inválido o expirado. Contacta al administrador.'
                    })
                }
                
        elif frontend_type == 'client':
            # Desde cliente frontend, solo permitir clientes
            if user_type != 'cliente':
                return {
                    'statusCode': 403,
                    'body': json.dumps({
                        'error': 'Acceso denegado. El portal cliente es solo para usuarios clientes'
                    })
                }
        else:
            # Si no se especifica frontend_type, asumimos cliente por defecto
            frontend_type = 'client'
            if user_type == 'staff':
                return {
                    'statusCode': 403,
                    'body': json.dumps({
                        'error': 'Registro de staff requiere especificar frontend_type: staff'
                    })
                }
        
        # Validación 3: Tipo de usuario válido
        if user_type not in ['cliente', 'staff']:
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'error': 'Tipo de usuario inválido. Debe ser "cliente" o "staff"'
                })
            }
        
        # Validación 4: Staff tier requerido para staff
        if user_type == 'staff':
            if not staff_tier:
                return {
                    'statusCode': 400,
                    'body': json.dumps({
                        'error': 'Usuarios staff requieren el campo staff_tier'
                    })
                }
            try:
                staff_tier = validate_staff_tier(staff_tier)
            except ValueError as e:
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': str(e)})
                }
        else:
            # Clientes no deben tener staff_tier
            staff_tier = None
        
        
        dynamodb = boto3.resource('dynamodb')
        t_usuarios = dynamodb.Table('t_usuarios')
        
        # Verificar si el email ya está registrado
        try:
            existing_user = t_usuarios.get_item(Key={'email': email})
            if 'Item' in existing_user:
                return {
                    'statusCode': 409,
                    'body': json.dumps({
                        'error': 'El email ya está registrado en el sistema'
                    })
                }
        except Exception as e:
            print(f"Error checking existing user: {str(e)}")
        
        ## REGISTRO
        hashed_password = hash_password(password)
        current_time = datetime.utcnow().isoformat()
        
        # Crear el item completo 
        user_item = {
            'user_id': str(uuid.uuid4()),  # ID único universal
            'email': email,
            'password': hashed_password,  
            'name': name,
            'phone': phone,
            'gender': gender,
            'user_type': user_type,
            'created_at': current_time,    
            'updated_at': current_time,    
            'is_active': True,             
            'last_login': None,            
            'registration_source': frontend_type  # 'client' o 'staff'
        }
        
        # Agregar campos específicos de staff
        if user_type == 'staff':
            user_item['staff_tier'] = staff_tier
            user_item['permissions'] = get_staff_permissions(staff_tier)
            user_item['is_verified'] = True  # Staff verificado por código
        else:
            user_item['is_verified'] = True  # Clientes requieren verificación por email
           
        # Guardar usuario en DynamoDB
        t_usuarios.put_item(Item=user_item)
        
        print(f"Usuario registrado exitosamente: {email}, tipo: {user_type}, frontend: {frontend_type}")

        ## RESPONSE
        response_data = {
            'message': 'Usuario registrado exitosamente',
            'user_id': user_item['user_id'],
            'email': email,
            'name': name,
            'user_type': user_type,
            'is_active': True,
            'registration_source': frontend_type,
            'requires_verification': not user_item['is_verified']
        }
        
        # Agregar información específica de staff a la respuesta
        if user_type == 'staff':
            response_data['staff_tier'] = staff_tier
            response_data['permissions'] = user_item['permissions']
            response_data['is_verified'] = True
        
        
        return {
            'statusCode': 201,
            'headers': {
                'Access-Control-Allow-Origin': '*',  # ✅ AGREGAR ESTO
                'Access-Control-Allow-Methods': 'POST, OPTIONS',  # ✅ AGREGAR ESTO
                'Access-Control-Allow-Headers': 'Content-Type, X-Amz-Date, Authorization, X-Api-Key, X-Amz-Security-Token',  # ✅ AGREGAR ESTO
                'Content-Type': 'application/json'
            },
            'body': json.dumps(response_data)  # Tu response_data actual
        }
        
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': {
                'Access-Control-Allow-Origin': '*',  # ✅ AGREGAR ESTO
                'Access-Control-Allow-Methods': 'POST, OPTIONS',  # ✅ AGREGAR ESTO
                'Access-Control-Allow-Headers': 'Content-Type, X-Amz-Date, Authorization, X-Api-Key, X-Amz-Security-Token',  # ✅ AGREGAR ESTO
                'Content-Type': 'application/json'
            },
            'body': json.dumps({'error': 'Internal server error'})
        }