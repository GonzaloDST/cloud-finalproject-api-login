import json
import os

# Headers CORS para todas las respuestas
CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS, GET',
    'Access-Control-Allow-Headers': 'Content-Type, X-Amz-Date, Authorization, X-Api-Key, X-Amz-Security-Token, Accept',
    'Content-Type': 'application/json'
}

def lambda_handler(event, context):
    """
    Maneja el logout de usuarios - principalmente para limpieza en el cliente
    """
    try:
        print("Logout event received:", json.dumps(event, indent=2))
        
        response_data = {
            'message': 'Logout exitoso',
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return {
            'statusCode': 200,
            'headers': CORS_HEADERS,
            'body': json.dumps(response_data)
        }

    except Exception as e:
        print("Exception in logout:", str(e))
        
        return {
            'statusCode': 500,
            'headers': CORS_HEADERS,
            'body': json.dumps({
                'error': 'Error interno del servidor',
                'code': 'INTERNAL_ERROR'
            })
        }