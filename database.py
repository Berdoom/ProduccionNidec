import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, Date, Text
from sqlalchemy.orm import sessionmaker, declarative_base, scoped_session
from werkzeug.security import generate_password_hash
from datetime import datetime

# Cargar variables de entorno desde el archivo .env
load_dotenv()

# --- Configuración de la Base de Datos ---
basedir = os.path.abspath(os.path.dirname(__file__))
default_sqlite_url = f"sqlite:///{os.path.join(basedir, 'produccion.db')}"
DATABASE_URL = os.getenv("DATABASE_URL") or default_sqlite_url
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL)
db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))

Base = declarative_base()
Base.query = db_session.query_property()

# --- Modelos de la Base de Datos (sin cambios) ---

class Usuario(Base):
    """Modelo para los usuarios del sistema."""
    __tablename__ = 'usuarios'
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(50), nullable=False) # Roles: ADMIN, IHP, FHP

    def __init__(self, username, password, role):
        self.username = username
        self.password_hash = generate_password_hash(password)
        self.role = role

class Pronostico(Base):
    """Modelo para almacenar los pronósticos de producción."""
    __tablename__ = 'pronosticos'
    id = Column(Integer, primary_key=True)
    fecha = Column(Date, nullable=False, index=True)
    grupo = Column(String(10), nullable=False, index=True)
    area = Column(String(50), nullable=False)
    turno = Column(String(20), nullable=False)
    valor_pronostico = Column(Integer)
    razon_desviacion = Column(Text)
    usuario_razon = Column(String(80))
    fecha_razon = Column(DateTime)
    status = Column(String(50), default='Nuevo', index=True)

class ProduccionCaptura(Base):
    """Modelo para almacenar la producción real capturada por hora."""
    __tablename__ = 'produccion_capturas'
    id = Column(Integer, primary_key=True)
    fecha = Column(Date, nullable=False, index=True)
    grupo = Column(String(10), nullable=False, index=True)
    area = Column(String(50), nullable=False)
    hora = Column(String(10), nullable=False)
    valor_producido = Column(Integer)
    usuario_captura = Column(String(80))
    fecha_captura = Column(DateTime, default=datetime.now)

class ActivityLog(Base):
    """Modelo para el registro de actividades importantes en el sistema."""
    __tablename__ = 'activity_logs'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.now, index=True)
    username = Column(String(80), index=True)
    action = Column(String(255))
    details = Column(Text)
    area_grupo = Column(String(50), index=True)

class OutputData(Base):
    """Modelo para almacenar los datos finales de 'Output'."""
    __tablename__ = 'output_data'
    id = Column(Integer, primary_key=True)
    fecha = Column(Date, nullable=False, index=True)
    grupo = Column(String(10), nullable=False, index=True)
    pronostico = Column(Integer)
    output = Column(Integer)
    usuario_captura = Column(String(80))
    fecha_captura = Column(DateTime, default=datetime.now)

# --- Funciones de Gestión de la Base de Datos ---

def init_db():
    """Crea todas las tablas si no existen."""
    print("Creando todas las tablas en la base de datos...")
    Base.metadata.create_all(bind=engine)
    print("Tablas creadas exitosamente.")

def create_default_admin():
    """Crea un usuario administrador por defecto si no existe ninguno."""
    admin_user = db_session.query(Usuario).filter_by(role='ADMIN').first()
    if not admin_user:
        print("No se encontraron usuarios ADMIN. Creando usuario por defecto...")
        default_admin = Usuario(username='admin', password='admin', role='ADMIN')
        db_session.add(default_admin)
        db_session.commit()
        print("Usuario 'admin' con contraseña 'admin' creado exitosamente.")
    else:
        print("Ya existe al menos un usuario administrador.")

# --- SCRIPT DE EJECUCIÓN DIRECTA ---

if __name__ == '__main__':
    """
    Este bloque se ejecuta cuando corres el archivo directamente desde la terminal
    usando el comando: python database.py
    
    Su propósito es crear la base de datos y el usuario admin inicial.
    """
    print("\nIniciando la configuración de la base de datos...")
    
    # 1. Crea las tablas
    init_db()
    
    # 2. Crea el usuario administrador por defecto
    create_default_admin()

    # Cierra la sesión de la base de datos para liberar la conexión
    db_session.remove()
    
    print("\nConfiguración finalizada. Puedes iniciar la aplicación Flask.")