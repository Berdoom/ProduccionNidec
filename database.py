import os
import sys
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, Date, Text
from sqlalchemy.orm import sessionmaker, declarative_base, scoped_session
from sqlalchemy.exc import IntegrityError, OperationalError
from werkzeug.security import generate_password_hash
from datetime import datetime

# Cargar variables de entorno desde el archivo .env (principalmente para desarrollo local)
load_dotenv()

# --- Configuración de la Base de Datos (Robusta para Producción) ---
DATABASE_URL = os.getenv("DATABASE_URL")

# En un entorno de producción como Render, DATABASE_URL DEBE estar definida.
if not DATABASE_URL:
    # Si estamos en Render (Render setea esta variable), es un error de configuración.
    if os.getenv('RENDER'):
        print("FATAL ERROR: La variable de entorno DATABASE_URL no está definida en el entorno de Render.", file=sys.stderr)
        print("Por favor, configura la variable en el dashboard de tu servicio web.", file=sys.stderr)
        sys.exit(1) # Detiene la aplicación si no puede encontrar la DB en producción.
    else:
        # Para desarrollo local, si no hay .env, usamos una base de datos SQLite por conveniencia.
        print("ADVERTENCIA: DATABASE_URL no encontrada. Usando base de datos SQLite local 'produccion.db' para desarrollo.")
        basedir = os.path.abspath(os.path.dirname(__file__))
        DATABASE_URL = f"sqlite:///{os.path.join(basedir, 'produccion.db')}"

# SQLAlchemy 1.4+ recomienda 'postgresql' en lugar de 'postgres' para nuevas conexiones.
# Render usa 'postgres://', así que hacemos el reemplazo para máxima compatibilidad.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    print("Configurando conexión a la base de datos PostgreSQL de producción...")
else:
    print(f"Configurando conexión a la base de datos local: {DATABASE_URL.split('///')[0]}...")

try:
    engine = create_engine(DATABASE_URL)
    db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))
except Exception as e:
    print(f"FATAL ERROR: No se pudo crear el motor de la base de datos con la URL proporcionada: {e}", file=sys.stderr)
    sys.exit(1)


Base = declarative_base()
Base.query = db_session.query_property()

# --- Modelos de la Base de Datos (Usuario Actualizado) ---

class Usuario(Base):
    """Modelo para los usuarios del sistema."""
    __tablename__ = 'usuarios'
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(50), nullable=False) # Roles: ADMIN, IHP, FHP
    # --- NUEVOS CAMPOS ---
    nombre_completo = Column(String(120), nullable=True)
    cargo = Column(String(80), nullable=True)

    def __init__(self, username, password, role, nombre_completo=None, cargo=None):
        self.username = username
        self.password_hash = generate_password_hash(password)
        self.role = role
        # --- ASIGNACIÓN DE NUEVOS CAMPOS ---
        self.nombre_completo = nombre_completo
        self.cargo = cargo

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
    print("Verificando y creando tablas si es necesario...")
    try:
        Base.metadata.create_all(bind=engine)
        print("Verificación de tablas completada exitosamente.")
    except OperationalError as e:
        print(f"ERROR OPERACIONAL al crear las tablas: {e}", file=sys.stderr)
        print("Esto puede indicar un problema de conexión con la base de datos o permisos insuficientes.", file=sys.stderr)
    except Exception as e:
        print(f"ERROR INESPERADO al crear las tablas: {e}", file=sys.stderr)

def create_default_admin():
    """Crea un usuario administrador por defecto si no existe ninguno. Es seguro de llamar múltiples veces."""
    print("Verificando la existencia del usuario administrador...")
    try:
        admin_user_exists = db_session.query(Usuario).filter_by(role='ADMIN').first()
        if not admin_user_exists:
            print("No se encontró usuario ADMIN. Intentando crear usuario por defecto 'admin'...")
            default_admin = Usuario(
                username='admin', 
                password='admin', 
                role='ADMIN', 
                nombre_completo='Administrador del Sistema', 
                cargo='Admin'
            )
            db_session.add(default_admin)
            try:
                db_session.commit()
                print("Usuario 'admin' con contraseña 'admin' creado exitosamente.")
            except IntegrityError:
                db_session.rollback()
                print("El usuario 'admin' ya fue creado, probablemente por otro proceso. Operación segura.")
            except Exception as e:
                db_session.rollback()
                print(f"ERROR al intentar guardar el usuario admin: {e}", file=sys.stderr)
        else:
            print("El usuario administrador ya existe.")
    except OperationalError as e:
        db_session.rollback()
        print(f"ERROR OPERACIONAL al verificar el usuario admin: {e}", file=sys.stderr)
        print("Asegúrate de que las tablas de la base de datos se hayan creado correctamente.", file=sys.stderr)
    except Exception as e:
        db_session.rollback()
        print(f"ERROR INESPERADO al verificar el usuario admin: {e}", file=sys.stderr)


# --- SCRIPT DE EJECUCIÓN DIRECTA (PARA USO MANUAL) ---
if __name__ == '__main__':
    print("\n--- INICIANDO CONFIGURACIÓN MANUAL DE LA BASE DE DATOS ---")
    init_db()
    create_default_admin()
    db_session.remove()
    print("\n--- CONFIGURACIÓN MANUAL FINALIZADA ---")