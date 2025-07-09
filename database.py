import os
import sys
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, Date, Text
from sqlalchemy.orm import sessionmaker, declarative_base, scoped_session
from werkzeug.security import generate_password_hash
from datetime import datetime

# Cargar variables de entorno desde el archivo .env
load_dotenv()

# --- Configuración de la Base de Datos ---
# Obtener la ruta absoluta del directorio del proyecto
basedir = os.path.abspath(os.path.dirname(__file__))

# Crear una URL por defecto para SQLite que sea relativa al proyecto
default_sqlite_url = f"sqlite:///{os.path.join(basedir, 'produccion.db')}"

# Usar la DATABASE_URL del .env si existe, si no, usar la URL de SQLite por defecto.
DATABASE_URL = os.getenv("DATABASE_URL") or default_sqlite_url

# Pequeña corrección para compatibilidad con Heroku/PostgreSQL
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
    grupo = Column(String(10), nullable=False, index=True) # IHP o FHP
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
    grupo = Column(String(10), nullable=False, index=True) # IHP o FHP
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
    grupo = Column(String(10), nullable=False, index=True) # IHP o FHP
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

def reset_database():
    """
    ¡ACCIÓN DESTRUCTIVA! Borra todas las tablas y las vuelve a crear.
    También crea un usuario administrador por defecto.
    """
    confirm = input("ADVERTENCIA: Estás a punto de borrar TODOS los datos de la base de datos. \n"
                    "Esta acción es irreversible. \n"
                    "Escribe 'BORRAR' para confirmar: ")
    if confirm == 'BORRAR':
        print("Borrando todas las tablas...")
        Base.metadata.drop_all(bind=engine)
        print("Tablas borradas.")
        init_db()
        create_default_admin()
        print("¡Base de datos reiniciada exitosamente!")
    else:
        print("Reinicio cancelado.")

if __name__ == '__main__':
    if len(sys.argv) > 1:
        command = sys.argv[1]
        if command == 'init':
            init_db()
        elif command == 'reset':
            reset_database()
        elif command == 'add-admin':
            create_default_admin()
        else:
            print(f"Comando desconocido: {command}")
            print("Comandos disponibles: init, reset, add-admin")
    else:
        print("Por favor, especifica un comando: init, reset, o add-admin")