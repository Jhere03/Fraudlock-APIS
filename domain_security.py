from flask import Flask, request, jsonify
from datetime import datetime
from urllib.parse import urlparse
import argparse
import re
import os


app = Flask(__name__)

# Umbral de antigüedad (en años)
AGE_THRESHOLD = 2.1  # 1 año como mínimo para considerarlo seguro

# Lista de TLDs válidos (simplificación, puede ampliarse)
VALID_TLDS = [".com", ".net", ".org", ".edu", ".gov", ".info", ".io", ".co", ".pe"]

# Función para extraer el dominio de una URL
def extract_domain(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc or parsed_url.path  # netloc para URLs con protocolo, path para las que no tienen
    if domain.startswith("www."):
        domain = domain[4:]  # Remover 'www.' si está presente
    
    # Si el dominio aún tiene un '/' al final, removerlo
    domain = domain.rstrip('/')
    
    return domain

# Función para validar si el dominio tiene un formato válido
def is_valid_domain(domain):
    # Verificar si tiene un TLD válido
    if not any(domain.endswith(tld) for tld in VALID_TLDS):
        return False

    # Usar una expresión regular para validar el formato general del dominio
    # El dominio debe tener letras, números, guiones y terminar con un TLD válido
    domain_regex = re.compile(r'^(?!\-)([A-Za-z0-9\-]{1,63})(?<!\-)\.[A-Za-z]{2,}$')
    if not domain_regex.match(domain):
        return False

    return True

# Función simulada para obtener la antigüedad real del dominio
def simulate_domain_creation_date(domain):
    """
    Simularemos la fecha de creación del dominio con reglas heurísticas mejoradas.
    """
    if not is_valid_domain(domain):
        return None, "Invalid domain format"
    
    # Heurística mejorada basada en la longitud y características del dominio
    if len(domain) <= 10:
        # Dominios cortos tienden a ser más antiguos
        simulated_creation_date = datetime.now().replace(year=datetime.now().year - 5)
    elif len(domain) <= 15:
        # Dominios medianos tienden a ser relativamente nuevos
        simulated_creation_date = datetime.now().replace(year=datetime.now().year - 2)
    else:
        # Dominios largos o con patrones raros son probablemente recientes
        simulated_creation_date = datetime.now().replace(year=datetime.now().year - 0.5)
    
    return simulated_creation_date, None

@app.route('/api/check_domain_security', methods=['POST'])
def check_domain_security():
    data = request.get_json()
    url = data.get('url')

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    domain = extract_domain(url)

    if not is_valid_domain(domain):
        # Si el dominio no es válido, lo marcamos como inseguro
        return jsonify({"domain": domain, "status": "Error", "reason": "Invalid domain format", "ESTADO": "fraud"}), 200

    try:
        # Simular obtener la fecha de creación usando la heurística mejorada
        creation_date, error = simulate_domain_creation_date(domain)
        if creation_date:
            domain_age = (datetime.now() - creation_date).days / 365.25  # Convertir días en años
        elif error:
            # Si hay un error, como un dominio no válido, lo consideramos inseguro
            return jsonify({"domain": domain, "status": "Error", "reason": error, "ESTADO": "fraud"}), 200

        # Evaluar el dominio basado en la antigüedad
        if domain_age >= AGE_THRESHOLD:
            return jsonify({"domain": domain, "status": "Safe", "age": domain_age, "ESTADO": "legal"})
        else:
            return jsonify({"domain": domain, "status": "Unsafe", "age": domain_age, "ESTADO": "fraud"})
    
    except Exception as e:
        # Si ocurre cualquier error (404 u otro), asumir que es fraudulento
        print(f"Error processing domain {domain}: {e}")
        return jsonify({"domain": domain, "status": "Error", "reason": "Assuming fraud due to an error", "ESTADO": "fraud"}), 200

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))  # Usa el puerto asignado por el entorno
    app.run(debug=True, host='0.0.0.0', port=port)  # Asegúrate de escuchar en todas las interfaces

