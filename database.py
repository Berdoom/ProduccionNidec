import os
import sys
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, Date, Text, inspect, text, UniqueConstraint
from sqlalchemy.orm import sessionmaker, declarative_base, scoped_session, relationship
from sqlalchemy.exc import IntegrityError, OperationalError, ProgrammingError, NoSuchTableError
from werkzeug.security import generate_password_hash
from datetime import datetime

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

# --- Bloque de configuración de DATABASE_URL (sin cambios) ---
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

# --- Modelos de la Base de Datos (sin cambios) ---
class Rol(Base):
    __tablename__ = 'roles'
    id = Column(Integer, primary_key=True)
    nombre = Column(String(50), unique=True, nullable=False)

class Turno(Base):
    __tablename__ = 'turnos'
    id = Column(Integer, primary_key=True)
    nombre = Column(String(50), unique=True, nullable=False)

class Usuario(Base):
    __tablename__ = 'usuarios'
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    nombre_completo = Column(String(120), nullable=True)
    cargo = Column(String(80), nullable=True)
    role_id = Column(Integer, ForeignKey('roles.id'))
    turno_id = Column(Integer, ForeignKey('turnos.id'))
    role = relationship('Rol', backref='usuarios')
    turno = relationship('Turno', backref='usuarios')
    def __init__(self, username, password, role_id, nombre_completo=None, cargo=None, turno_id=None):
        self.username = username
        self.password_hash = generate_password_hash(password)
        self.role_id = role_id
        self.nombre_completo = nombre_completo
        self.cargo = cargo
        self.turno_id = turno_id

class Pronostico(Base): __tablename__ = 'pronosticos'; id = Column(Integer, primary_key=True); fecha = Column(Date, nullable=False, index=True); grupo = Column(String(10), nullable=False, index=True); area = Column(String(50), nullable=False); turno = Column(String(20), nullable=False); valor_pronostico = Column(Integer); razon_desviacion = Column(Text); usuario_razon = Column(String(80)); fecha_razon = Column(DateTime); status = Column(String(50), default='Nuevo', index=True); __table_args__ = (UniqueConstraint('fecha', 'grupo', 'area', 'turno', name='_fecha_grupo_area_turno_uc'),)
class ProduccionCaptura(Base): __tablename__ = 'produccion_capturas'; id = Column(Integer, primary_key=True); fecha = Column(Date, nullable=False, index=True); grupo = Column(String(10), nullable=False, index=True); area = Column(String(50), nullable=False); hora = Column(String(10), nullable=False); valor_producido = Column(Integer); usuario_captura = Column(String(80)); fecha_captura = Column(DateTime, default=datetime.utcnow); __table_args__ = (UniqueConstraint('fecha', 'grupo', 'area', 'hora', name='_fecha_grupo_area_hora_uc'),)
class ActivityLog(Base): __tablename__ = 'activity_logs'; id = Column(Integer, primary_key=True); timestamp = Column(DateTime, default=datetime.utcnow, index=True); username = Column(String(80), index=True); action = Column(String(255)); details = Column(Text); area_grupo = Column(String(50), index=True); ip_address = Column(String(45)); category = Column(String(50)); severity = Column(String(20))
class OutputData(Base): __tablename__ = 'output_data'; id = Column(Integer, primary_key=True); fecha = Column(Date, nullable=False, index=True); grupo = Column(String(10), nullable=False, index=True); pronostico = Column(Integer); output = Column(Integer); usuario_captura = Column(String(80)); fecha_captura = Column(DateTime, default=datetime.utcnow)
class SolicitudCorreccion(Base): __tablename__ = 'solicitudes_correccion'; id = Column(Integer, primary_key=True); timestamp = Column(DateTime, default=datetime.utcnow, index=True); usuario_solicitante = Column(String(80), nullable=False); fecha_problema = Column(Date, nullable=False); grupo = Column(String(10), nullable=False); area = Column(String(50)); turno = Column(String(20)); tipo_error = Column(String(100), nullable=False); descripcion = Column(Text, nullable=False); status = Column(String(50), default='Pendiente', index=True); admin_username = Column(String(80)); fecha_resolucion = Column(DateTime); admin_notas = Column(Text)

def _execute_migration(connection):
    """
    Ejecuta la migración de datos de texto a IDs relacionales de forma segura.
    """
    print("Iniciando migración de datos de roles y turnos...")
    
    # --- NUEVO: Añadir las columnas ANTES de usarlas ---
    print("Paso 1: Añadiendo columnas 'role_id' y 'turno_id' a la tabla 'usuarios'...")
    connection.execute(text("ALTER TABLE usuarios ADD COLUMN role_id INTEGER"))
    connection.execute(text("ALTER TABLE usuarios ADD COLUMN turno_id INTEGER"))
    
    # --- NUEVO: Añadir las Foreign Keys ---
    print("Paso 2: Añadiendo Foreign Key constraints...")
    connection.execute(text("ALTER TABLE usuarios ADD CONSTRAINT fk_usuarios_role_id FOREIGN KEY (role_id) REFERENCES roles (id)"))
    connection.execute(text("ALTER TABLE usuarios ADD CONSTRAINT fk_usuarios_turno_id FOREIGN KEY (turno_id) REFERENCES turnos (id)"))

    print("Paso 3: Poblando tablas 'roles' y 'turnos'...")
    old_roles = connection.execute(text("SELECT DISTINCT role FROM usuarios WHERE role IS NOT NULL")).fetchall()
    old_turnos = connection.execute(text("SELECT DISTINCT turno FROM usuarios WHERE turno IS NOT NULL")).fetchall()

    is_postgres = connection.dialect.name == 'postgresql'
    for (role_name,) in old_roles:
        if is_postgres: connection.execute(text("INSERT INTO roles (nombre) VALUES (:name) ON CONFLICT (nombre) DO NOTHING"), {"name": role_name})
        else: connection.execute(text("INSERT OR IGNORE INTO roles (nombre) VALUES (:name)"), {"name": role_name})

    for (turno_name,) in old_turnos:
        if is_postgres: connection.execute(text("INSERT INTO turnos (nombre) VALUES (:name) ON CONFLICT (nombre) DO NOTHING"), {"name": turno_name})
        else: connection.execute(text("INSERT OR IGNORE INTO turnos (nombre) VALUES (:name)"), {"name": turno_name})
    
    print("Paso 4: Actualizando foreign keys en la tabla 'usuarios'...")
    connection.execute(text("UPDATE usuarios SET role_id = (SELECT id FROM roles WHERE nombre = usuarios.role)"))
    connection.execute(text("UPDATE usuarios SET turno_id = (SELECT id FROM turnos WHERE nombre = usuarios.turno)"))
    
    print("Paso 5: Renombrando columnas antiguas para finalizar...")
    connection.execute(text("ALTER TABLE usuarios RENAME COLUMN role TO role_old"))
    connection.execute(text("ALTER TABLE usuarios RENAME COLUMN turno TO turno_old"))
    
    print("¡Migración completada exitosamente!")

def init_db():
    print("Verificando y creando tablas si es necesario...")
    Base.metadata.create_all(bind=engine)
    print("Verificación de tablas completada.")

    inspector = inspect(engine)
    try:
        user_columns = [c['name'] for c in inspector.get_columns('usuarios')]
        
        # El disparador para la migración es la existencia de la columna 'role' (la antigua).
        if 'role' in user_columns:
            print("Detectada estructura de datos antigua. Se requiere migración.")
            try:
                with engine.connect() as connection:
                    with connection.begin():
                        _execute_migration(connection)
            except Exception as e:
                print(f"ERROR CRÍTICO DURANTE LA MIGRACIÓN: {e}", file=sys.stderr)
                print("La migración falló. La base de datos podría estar en un estado inconsistente. Por favor, restaura desde una copia de seguridad.", file=sys.stderr)
        else:
            print("La estructura de la base de datos está actualizada. No se requiere migración.")

    except NoSuchTableError:
        print("La tabla 'usuarios' no existía, se acaba de crear. No se requiere migración.")
    except Exception as e:
        print(f"ERROR INESPERADO durante la inicialización de la BD: {e}", file=sys.stderr)

def create_default_admin():
    print("Verificando la existencia del usuario administrador...")
    try:
        default_roles = ['ADMIN', 'IHP', 'FHP', 'PROGRAMA_LM']
        for role_name in default_roles:
            if not db_session.query(Rol).filter_by(nombre=role_name).first():
                db_session.add(Rol(nombre=role_name))
        
        default_turnos = ['Turno A', 'Turno B', 'Turno C', 'N/A']
        for turno_name in default_turnos:
            if not db_session.query(Turno).filter_by(nombre=turno_name).first():
                db_session.add(Turno(nombre=turno_name))
        db_session.commit()

        admin_role = db_session.query(Rol).filter_by(nombre='ADMIN').one_or_none()
        if not admin_role:
             print("ERROR CRÍTICO: El rol ADMIN no pudo ser creado o encontrado.", file=sys.stderr)
             return

        admin_user_exists = db_session.query(Usuario).filter_by(role_id=admin_role.id).first()

        if not admin_user_exists:
            print("No se encontró usuario ADMIN. Creando usuario por defecto 'admin'...")
            na_turno = db_session.query(Turno).filter_by(nombre='N/A').one()
            default_admin = Usuario(
                username='admin', 
                password='admin', 
                role_id=admin_role.id,
                nombre_completo='Administrador del Sistema', 
                cargo='Admin',
                turno_id=na_turno.id
            )
            db_session.add(default_admin)
            db_session.commit()
            print("Usuario 'admin' creado exitosamente.")
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