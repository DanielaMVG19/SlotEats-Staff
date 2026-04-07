from flask import Flask, request, jsonify, render_template
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from pymongo import MongoClient
import random, string, os

server1 = Flask(__name__)
CORS(server1)
bcrypt = Bcrypt(server1)

# Conexión a Mongo Atlas
MONGO_URI = "mongodb+srv://whosmarny:Dnxlsmth.6@cluster0.eazfo3x.mongodb.net/SlotEatsDB?retryWrites=true&w=majority"
client = MongoClient(MONGO_URI)
db = client.SlotEatsDB

# Colecciones
repartidores = db.empleados 
pedidos_col = db.pedidos # <--- Nueva conexión para los pedidos

@server1.route('/')
def home():
    return render_template('loginrepartidor.html')

# Ruta para que pedidos.html cargue los datos
@server1.route('/pedidos.html')
def pedidos_page():
    return render_template('pedidos.html')

@server1.route('/login-repartidor', methods=['POST'])
def login():
    data = request.json
    email = data.get('email', '').lower()
    password = data.get('password')

    if not email.endswith('@sloteats.com'):
        return jsonify({"msg": "Acceso Denegado: Solo personal @sloteats.com"}), 403

    user = repartidores.find_one({"email": email})
    if not user:
        return jsonify({"msg": "Repartidor no encontrado"}), 404

    if user.get('estaBloqueado', False):
        return jsonify({"msg": f"CUENTA BLOQUEADA. Código: {user.get('codigoDesbloqueo')}"}), 401

    if bcrypt.check_password_hash(user['password'], password):
        repartidores.update_one({"email": email}, {"$set": {"intentosFallidos": 0}})
        # Importante: Enviamos el email para que el HTML sepa de quién son los pedidos
        return jsonify({
            "msg": f"¡Bienvenido {user['nombre']}!", 
            "nombre": user['nombre'],
            "email": email
        }), 200
    else:
        intentos = user.get('intentosFallidos', 0) + 1
        if intentos >= 4:
            codigo = ''.join(random.choices(string.digits, k=6))
            repartidores.update_one({"email": email}, {"$set": {"estaBloqueado": True, "codigoDesbloqueo": codigo, "intentosFallidos": intentos}})
            return jsonify({"msg": "Límite superado. Cuenta Bloqueada."}), 401
        
        repartidores.update_one({"email": email}, {"$set": {"intentosFallidos": intentos}})
        return jsonify({"msg": f"Contraseña incorrecta. {intentos}/4"}), 401

# API para consultar los pedidos desde el HTML
@server1.route('/mis-pedidos/<email>')
def obtener_pedidos(email):
    # El repartidor ve pedidos que NO están entregados (pendientes)
    query = {"estatus": {"$ne": "Entregado"}}
    lista_pedidos = list(pedidos_col.find(query))
    
    # Formateamos el ID de Mongo para que JS no se confunda
    for p in lista_pedidos:
        p['_id'] = str(p['_id'])
        
    return jsonify(lista_pedidos)

@server1.route('/unlock-repartidor', methods=['POST'])
def unlock():
    data = request.json
    user = repartidores.find_one({"email": data.get('email')})
    if user and str(user.get('codigoDesbloqueo')) == str(data.get('codigo')):
        hash_pass = bcrypt.generate_password_hash(data.get('nuevaPassword')).decode('utf-8')
        repartidores.update_one({"email": data.get('email')}, {
            "$set": {"password": hash_pass, "estaBloqueado": False, "intentosFallidos": 0, "codigoDesbloqueo": None}
        })
        return jsonify({"msg": "Cuenta desbloqueada exitosamente."}), 200
    return jsonify({"msg": "Código incorrecto"}), 400

@server1.route('/fix-passwords')
def fix_passwords():
    all_users = repartidores.find()
    count = 0
    for user in all_users:
        if not user['password'].startswith('$2b$'):
            nuevo_hash = bcrypt.generate_password_hash(user['password']).decode('utf-8')
            repartidores.update_one({"_id": user["_id"]}, {"$set": {"password": nuevo_hash}})
            count += 1
    return f"¡Listo! Se actualizaron {count} contraseñas."

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    server1.run(host='0.0.0.0', port=port)
