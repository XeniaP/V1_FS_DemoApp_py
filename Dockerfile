FROM python:3.9

WORKDIR /app

# Instalar dependencias
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el código de la aplicación
COPY . .

# Exponer el puerto 80
EXPOSE 80

# Ejecutar la aplicación
CMD ["python", "app.py"]