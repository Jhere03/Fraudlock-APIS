from flask import Flask, jsonify
from flask_cors import CORS
import os
from ssl_check import check_ssl
from url_similarity import check_url_similarity
from domain_security import check_domain_security
from populary_domain import check_domain_popularity
from metadata_check import check_metadata

app = Flask(__name__)
CORS(app)

# Ruta principal para la página de inicio
@app.route('/')
def home():
    return "Bienvenido a Fraudlock APIs. Accede a las APIs específicas para verificar la seguridad de los dominios."

# Registrar las rutas de todas las APIs
@app.route('/api/check_ssl', methods=['POST'])
def check_ssl_route():
    return check_ssl()

@app.route('/api/check_url_similarity', methods=['POST'])
def check_url_similarity_route():
    return check_url_similarity()

@app.route('/api/check_domain_security', methods=['POST'])
def check_domain_security_route():
    return check_domain_security()

@app.route('/api/check_domain_popularity', methods=['POST'])
def check_domain_popularity_route():
    return check_domain_popularity()

@app.route('/api/check_metadata', methods=['POST'])
def check_metadata_route():
    return check_metadata()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
