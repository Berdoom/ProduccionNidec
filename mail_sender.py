import os
import sys  
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# --- Configuración del Correo (Leer desde variables de entorno) ---
MAIL_SERVER = os.getenv('MAIL_SERVER')
MAIL_PORT = int(os.getenv('MAIL_PORT', 587))
MAIL_USERNAME = os.getenv('MAIL_USERNAME') # Para SendGrid, esto es "apikey"
MAIL_PASSWORD = os.getenv('MAIL_PASSWORD') # La clave de API de SendGrid
MAIL_SENDER = os.getenv('MAIL_SENDER')     # Tu correo verificado

def send_email(recipient, subject, body_html):
    """
    Función genérica para enviar un correo electrónico.
    """
    if not all([MAIL_SERVER, MAIL_PORT, MAIL_USERNAME, MAIL_PASSWORD, MAIL_SENDER, recipient]):
        print("ERROR: Faltan variables de entorno para el envío de correo. No se puede enviar.", file=sys.stderr)
        return False

    print(f"Preparando correo para {recipient} con asunto: '{subject}'...")
    
    msg = MIMEMultipart()
    msg['From'] = MAIL_SENDER
    msg['To'] = recipient
    msg['Subject'] = subject
    msg.attach(MIMEText(body_html, 'html'))
    
    try:
        with smtplib.SMTP(MAIL_SERVER, MAIL_PORT) as server:
            server.starttls()
            server.login(MAIL_USERNAME, MAIL_PASSWORD)
            server.send_message(msg)
        print("Correo enviado exitosamente.")
        return True
    except Exception as e:
        print(f"ERROR: No se pudo enviar el correo. Error: {e}", file=sys.stderr)
        return False