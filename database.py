import os
import sys
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, Date, Text, inspect, text
from sqlalchemy.orm import sessionmaker, declarative_base, scoped_session
from sqlalchemy.exc import IntegrityError, OperationalError
from werkzeug.security import generate_password_hash
from datetime import datetime

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    if os.getenv('RENDER'):
        print("FATAL ERROR: La variable de entorno DATABASE_URL no está definida en el entorno de Render.", file=sys.stderr)
        sys.exit(1)
    else:
        print("ADVERTENCIA: La variable de entorno DATABASE_URL no fue encontrada.")
        try:
            project_root = os.path.dirname(os.path.abspath(__file__))
            instance_path = os.path.join(project_root, 'instance')
            os.makedirs(instance_path, exist_ok=True)
            db_path = os.path.join(instance_path, 'produccion.db')
            DATABASE_URL = f'sqlite:///{db_path}'
            print(f"Usando una base de datos SQLite local por defecto en: '{db_path}'")
        except Exception as e:
            print(f"FATAL ERROR: No se pudo crear la ruta para la base de datos local: {e}", file=sys.stderr)
            sys.exit(1)

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    print("Configurando conexión a la base de datos PostgreSQL de producción...")
else:
    db_type = DATABASE_URL.split(':')[0]
    print(f"Configurando conexión a la base de datos local del tipo: {db_type}...")

try:
    engine = create_engine(DATABASE_URL)
    db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))
except Exception as e:
    print(f"FATAL ERROR: No se pudo crear el motor de la base de datos con la URL proporcionada: {e}", file=sys.stderr)
    sys.exit(1)

Base = declarative_base()
Base.query = db_session.query_property()

class Usuario(Base):
    __tablename__ = 'usuarios'
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(50), nullable=False)
    nombre_completo = Column(String(120), nullable=True)
    cargo = Column(String(80), nullable=True)
    turno = Column(String(20), nullable=True)

    def __init__(self, username, password, role, nombre_completo=None, cargo=None, turno=None):
        self.username = username
        self.password_hash = generate_password_hash(password)
        self.role = role
        self.nombre_completo = nombre_completo
        self.cargo = cargo
        self.turno = turno

class Pronostico(Base):
    __tablename__ = 'pronosticos'
    id = Column(Integer, primary_key=True)
    fecha = Column(Date, nullable=False, index=True)
    grupo = Column(String(10), nullable=False, index=True)
    area = Column(String(50), nullable=False)
    turno = Column(String(20), nullable=False)
    valor_pronostico = Column(Integer)
    razon_desviacion = Column(Text)
    usuario_razon = Column(String(80))
    # CAMBIO: Usar UTC para la hora de la razón
    fecha_razon = Column(DateTime)
    status = Column(String(50), default='Nuevo', index=True)

class ProduccionCaptura(Base):
    __tablename__ = 'produccion_capturas'
    id = Column(Integer, primary_key=True)
    fecha = Column(Date, nullable=False, index=True)
    grupo = Column(String(10), nullable=False, index=True)
    area = Column(String(50), nullable=False)
    hora = Column(String(10), nullable=False)
    valor_producido = Column(Integer)
    usuario_captura = Column(String(80))
    # CAMBIO: Usar UTC para la hora de captura
    fecha_captura = Column(DateTime, default=datetime.utcnow)

class ActivityLog(Base):
    __tablename__ = 'activity_logs'
    id = Column(Integer, primary_key=True)
    # CAMBIO: Usar UTC para el timestamp del log
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    username = Column(String(80), index=True)
    action = Column(String(255))
    details = Column(Text)
    area_grupo = Column(String(50), index=True)
    ip_address = Column(String(45))
    category = Column(String(50))
    severity = Column(String(20))

class OutputData(Base):
    __tablename__ = 'output_data'
    id = Column(Integer, primary_key=True)
    fecha = Column(Date, nullable=False, index=True)
    grupo = Column(String(10), nullable=False, index=True)
    pronostico = Column(Integer)
    output = Column(Integer)
    usuario_captura = Column(String(80))
    # CAMBIO: Usar UTC para la hora de captura
    fecha_captura = Column(DateTime, default=datetime.utcnow)

def init_db():
    print("Verificando y creando tablas si es necesario...")
    try:
        Base.metadata.create_all(bind=engine)
        print("Verificación de tablas completada exitosamente.")
        inspector = inspect(engine)
        user_columns = [c['name'] for c in inspector.get_columns('usuarios')]
        if 'turno' not in user_columns:
            print("ADVERTENCIA: La columna 'turno' no se encontró. Añadiéndola...")
            with engine.connect() as connection:
                connection.execute(text('ALTER TABLE usuarios ADD COLUMN turno VARCHAR(20)'))
                connection.commit()
            print("Columna 'turno' añadida exitosamente.")
        log_columns = [c['name'] for c in inspector.get_columns('activity_logs')]
        new_log_cols = {'ip_address': 'VARCHAR(45)', 'category': 'VARCHAR(50)', 'severity': 'VARCHAR(20)'}
        for col, col_type in new_log_cols.items():
            if col not in log_columns:
                print(f"ADVERTENCIA: La columna '{col}' no se encontró en 'activity_logs'. Añadiéndola...")
                with engine.connect() as connection:
                    connection.execute(text(f'ALTER TABLE activity_logs ADD COLUMN {col} {col_type}'))
                    connection.commit()
                print(f"Columna '{col}' añadida exitosamente.")
    except OperationalError as e:
        print(f"ERROR OPERACIONAL al inicializar la base de datos: {e}", file=sys.stderr)
    except Exception as e:
        print(f"ERROR INESPERADO al inicializar la base de datos: {e}", file=sys.stderr)

def create_default_admin():
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
                cargo='Admin',
                turno='N/A'
            )
            db_session.add(default_admin)
            db_session.commit()
            print("Usuario 'admin' con contraseña 'admin' creado exitosamente.")
        else:
            print("El usuario administrador ya existe.")
    except Exception as e:
        db_session.rollback()
        print(f"ERROR al verificar/crear el usuario admin: {e}", file=sys.stderr)

if __name__ == '__main__':
    print("\n--- INICIANDO CONFIGURACIÓN MANUAL DE LA BASE DE DATOS ---")
    init_db()
    create_default_admin()
    db_session.remove()
    print("\n--- CONFIGURACIÓN MANUAL FINALIZADA ---")