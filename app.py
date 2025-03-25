from flask import Flask, request, jsonify, send_file
from flask_mysqldb import MySQL
import jwt ,pyotp ,qrcode,io ,bcrypt,datetime


app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'myapp'
app.config['JWT_SECRET_KEY'] = 'Maryam'

mysql = MySQL(app)

###########################################################################################################

@app.route('/signup', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    secret = pyotp.random_base32()

    Cursor = mysql.connection.cursor()
    Cursor.execute("INSERT INTO users (username, password, twofa_secret) VALUES (%s, %s, %s)",
                (username, hashed_password, secret))
    mysql.connection.commit()
    Cursor.close()

    return jsonify({'message': 'User registered successfully'}), 201

###########################################################################################################

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    Cursor = mysql.connection.cursor()
    Cursor.execute("SELECT password, twofa_secret FROM users WHERE username=%s", (username,))
    user = Cursor.fetchone()
    Cursor.close()

    if not user:
        return jsonify({'message': 'Invalid username or password'}), 401

    hashed_password, secret = user

    if not bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
        return jsonify({'message': 'Invalid username or password'}), 401

    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name='myapp')
    qr = qrcode.make(uri)
    img = io.BytesIO()
    qr.save(img)
    img.seek(0)

    return send_file(img, mimetype='image/png')

###########################################################################################################

@app.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    data = request.json
    username = data.get('username')
    code = data.get('code')

    if not username or not code:
        return jsonify({'message': 'Username and code are required'}), 400

    Cursor = mysql.connection.cursor()
    Cursor.execute("SELECT twofa_secret FROM users WHERE username=%s", (username,))
    user = Cursor.fetchone()
    Cursor.close()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    secret = user[0]
    totp = pyotp.TOTP(secret)
    if not totp.verify(code):
        return jsonify({'message': 'Invalid or expired 2FA code'}), 401

    access_token = jwt.encode({'identity': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)},
                              app.config['JWT_SECRET_KEY'], algorithm='HS256')
    return jsonify({'message': 'Login successful', 'access_token': access_token})




###########################################################################################################

@app.route('/products', methods=['POST'])
def CreateProduct():
    data = request.json
    name = data.get('name')
    description = data.get('description', '')
    price = data.get('price')
    quantity = data.get('quantity')
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token is missing'}), 401
    try:
        decoded_token = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        request.user = decoded_token['identity']
    except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

    if not name or price is None or quantity is None:
        return jsonify({"message": "Missing required fields"}), 400

    Cursor = mysql.connection.cursor()
    Cursor.execute("INSERT INTO products (name, description, price, quantity) VALUES (%s, %s, %s, %s)", 
                (name, description, price, quantity))
    mysql.connection.commit()
    Cursor.close()

    return jsonify({"message": "Product created successfully"})

##################################################################################################

@app.route('/products', methods=['GET'])
def GetProducts():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token is missing'}), 401
    try:
        decoded_token = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        request.user = decoded_token['identity']
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

    Cursor = mysql.connection.cursor()
    Cursor.execute("SELECT * FROM products")
    products = Cursor.fetchall()
    Cursor.close()

    return jsonify([{"id": row[0], "name": row[1], "description": row[2], "price": row[3], "quantity": row[4]} for row in products])

##################################################################################################

@app.route('/products/<int:product_id>', methods=['PUT'])
def UpdateProduct(product_id):
    data = request.json
    name = data.get('name')
    description = data.get('description')
    price = data.get('price')
    quantity = data.get('quantity')
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token is missing'}), 401
    try:
        decoded_token = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        request.user = decoded_token['identity']
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

    Cursor = mysql.connection.cursor()
    Cursor.execute("UPDATE products SET name=%s, description=%s, price=%s, quantity=%s WHERE id=%s",
                (name, description, price, quantity, product_id))
    mysql.connection.commit()
    Cursor.close()

    return jsonify({"message": "Product updated successfully"})

##################################################################################################

@app.route('/products/<int:product_id>', methods=['DELETE'])

def DeleteProduct(product_id):
    Cursor = mysql.connection.cursor()
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token is missing'}), 401
    try:
        decoded_token = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        request.user = decoded_token['identity']
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401
    
    Cursor.execute("DELETE FROM products WHERE id=%s", (product_id,))
    mysql.connection.commit()
    Cursor.close()
    return jsonify({"message": "Product deleted successfully"})

###########################################################################################################

if __name__ == '__main__':
    app.run(debug=True)
