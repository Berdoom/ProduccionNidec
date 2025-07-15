import os
import sys
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, Date, Text, inspect, text, UniqueConstraint, Boolean
from sqlalchemy.orm import sessionmaker, declarative_base, scoped_session, relationship
from sqlalchemy.exc import IntegrityError, OperationalError, ProgrammingError, NoSuchTableError
from werkzeug.security import generate_password_hash
from datetime import datetime

# --- (Configuración de la BD no cambia) ---
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
try:
    engine = create_engine(DATABASE_URL)
    db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))
except Exception as e:
    print(f"FATAL ERROR: No se pudo crear el motor de la base de datos con la URL proporcionada: {e}", file=sys.stderr)
    sys.exit(1)
Base = declarative_base()
Base.query = db_session.query_property()


# --- (MODELOS DE DATOS NO CAMBIAN) ---
class Rol(Base): __tablename__ = 'roles'; id = Column(Integer, primary_key=True); nombre = Column(String(50), unique=True, nullable=False)
class Turno(Base): __tablename__ = 'turnos'; id = Column(Integer, primary_key=True); nombre = Column(String(50), unique=True, nullable=False)
class Usuario(Base):
    __tablename__ = 'usuarios'
    id = Column(Integer, primary_key=True); username = Column(String(80), unique=True, nullable=False); password_hash = Column(String(256), nullable=False); nombre_completo = Column(String(120), nullable=True); cargo = Column(String(80), nullable=True); role_id = Column(Integer, ForeignKey('roles.id')); turno_id = Column(Integer, ForeignKey('turnos.id'))
    role = relationship('Rol', backref='usuarios'); turno = relationship('Turno', backref='usuarios')
    def __init__(self, username, password, role_id, nombre_completo=None, cargo=None, turno_id=None): self.username = username; self.password_hash = generate_password_hash(password); self.role_id = role_id; self.nombre_completo = nombre_completo; self.cargo = cargo; self.turno_id = turno_id
class Pronostico(Base): __tablename__ = 'pronosticos'; id = Column(Integer, primary_key=True); fecha = Column(Date, nullable=False, index=True); grupo = Column(String(10), nullable=False, index=True); area = Column(String(50), nullable=False); turno = Column(String(20), nullable=False); valor_pronostico = Column(Integer); razon_desviacion = Column(Text); usuario_razon = Column(String(80)); fecha_razon = Column(DateTime); status = Column(String(50), default='Nuevo', index=True); __table_args__ = (UniqueConstraint('fecha', 'grupo', 'area', 'turno', name='_fecha_grupo_area_turno_uc'),)
class ProduccionCaptura(Base): __tablename__ = 'produccion_capturas'; id = Column(Integer, primary_key=True); fecha = Column(Date, nullable=False, index=True); grupo = Column(String(10), nullable=False, index=True); area = Column(String(50), nullable=False); hora = Column(String(10), nullable=False); valor_producido = Column(Integer); usuario_captura = Column(String(80)); fecha_captura = Column(DateTime, default=datetime.utcnow); __table_args__ = (UniqueConstraint('fecha', 'grupo', 'area', 'hora', name='_fecha_grupo_area_hora_uc'),)
class ActivityLog(Base): __tablename__ = 'activity_logs'; id = Column(Integer, primary_key=True); timestamp = Column(DateTime, default=datetime.utcnow, index=True); username = Column(String(80), index=True); action = Column(String(255)); details = Column(Text); area_grupo = Column(String(50), index=True); ip_address = Column(String(45)); category = Column(String(50)); severity = Column(String(20))
class OutputData(Base): __tablename__ = 'output_data'; id = Column(Integer, primary_key=True); fecha = Column(Date, nullable=False, index=True); grupo = Column(String(10), nullable=False, index=True); pronostico = Column(Integer); output = Column(Integer); usuario_captura = Column(String(80)); fecha_captura = Column(DateTime, default=datetime.utcnow)
class SolicitudCorreccion(Base): __tablename__ = 'solicitudes_correccion'; id = Column(Integer, primary_key=True); timestamp = Column(DateTime, default=datetime.utcnow, index=True); usuario_solicitante = Column(String(80), nullable=False); fecha_problema = Column(Date, nullable=False); grupo = Column(String(10), nullable=False); area = Column(String(50)); turno = Column(String(20)); tipo_error = Column(String(100), nullable=False); descripcion = Column(Text, nullable=False); status = Column(String(50), default='Pendiente', index=True); admin_username = Column(String(80)); fecha_resolucion = Column(DateTime); admin_notas = Column(Text)
class OrdenLM(Base):
    __tablename__ = 'ordenes_lm'
    id = Column(Integer, primary_key=True)
    wip_order = Column(String(100), unique=True, nullable=False)
    item = Column(String(100))
    qty = Column(Integer, nullable=False, default=1)
    timestamp = Column(DateTime, default=datetime.utcnow)
    celdas = relationship('DatoCeldaLM', backref='orden', cascade='all, delete-orphan')
    # --- NUEVA COLUMNA PARA EL ESTADO ---
    # Por defecto, todas las nuevas órdenes estarán 'Pendientes'
    status = Column(String(50), default='Pendiente', nullable=False, index=True)
class ColumnaLM(Base): __tablename__ = 'columnas_lm'; id = Column(Integer, primary_key=True); nombre = Column(String(100), unique=True, nullable=False); orden = Column(Integer, default=100); editable_por_lm = Column(Boolean, default=True, nullable=False); celdas = relationship('DatoCeldaLM', backref='columna', cascade='all, delete-orphan')
class DatoCeldaLM(Base):
    __tablename__ = 'datos_celda_lm'
    id = Column(Integer, primary_key=True)
    orden_id = Column(Integer, ForeignKey('ordenes_lm.id', ondelete='CASCADE'), nullable=False)
    columna_id = Column(Integer, ForeignKey('columnas_lm.id', ondelete='CASCADE'), nullable=False)
    valor = Column(Text)
    estilos_css = Column(Text, nullable=True) 
    __table_args__ = (UniqueConstraint('orden_id', 'columna_id', name='_orden_columna_uc'),)


# =================================================================
# === FUNCIÓN init_db() CON MIGRACIÓN Y AUTO-CORRECCIÓN DE ESQUEMA ===
# =================================================================
def init_db():
    print("Verificando y creando tablas si es necesario...")
    Base.metadata.create_all(bind=engine)
    print("Verificación de tablas completada.")

    inspector = inspect(engine)
    try:
        # --- LÓGICA DE MIGRACIÓN Y AUTO-CORRECCIÓN PARA LA TABLA 'usuarios' ---
        if inspector.has_table('usuarios'):
            user_columns = {c['name'] for c in inspector.get_columns('usuarios')}
            with engine.connect() as connection:
                if connection.dialect.name == 'postgresql':
                     connection.execution_options(isolation_level="AUTOCOMMIT")
                if 'role_old' in user_columns:
                    print("Detectada columna obsoleta 'role_old'. Eliminándola...")
                    connection.execute(text("ALTER TABLE usuarios DROP COLUMN role_old;"))
                    print("'role_old' eliminada.")
                if 'turno_old' in user_columns:
                    print("Detectada columna obsoleta 'turno_old'. Eliminándola...")
                    connection.execute(text("ALTER TABLE usuarios DROP COLUMN turno_old;"))
                    print("'turno_old' eliminada.")
            # Volvemos a leer las columnas después de los posibles cambios
            user_columns = {c['name'] for c in inspector.get_columns('usuarios')}
            if 'role' in user_columns:
                print("Detectada estructura de datos antigua (columna 'role'). Se requiere migración.")
                _execute_migration()
            else:
                print("La estructura de la tabla 'usuarios' está actualizada.")
        else:
            print("La tabla 'usuarios' no existía, se acaba de crear.")

        # --- LÓGICA DE AUTO-CORRECCIÓN PARA LA TABLA 'datos_celda_lm' (NUEVA) ---
        if inspector.has_table('datos_celda_lm'):
            celda_columns = {c['name'] for c in inspector.get_columns('datos_celda_lm')}
            if 'estilos_css' not in celda_columns:
                print("La columna 'estilos_css' no existe en 'datos_celda_lm'. Añadiéndola...")
                with engine.connect() as connection:
                    if connection.dialect.name == 'postgresql':
                        connection.execution_options(isolation_level="AUTOCOMMIT")
                    connection.execute(text("ALTER TABLE datos_celda_lm ADD COLUMN estilos_css TEXT;"))
                print("Columna 'estilos_css' añadida exitosamente.")
        else:
            print("La tabla 'datos_celda_lm' no existía. Se acaba de crear con el schema correcto.")

        # --- LÓGICA DE AUTO-CORRECCIÓN PARA LA TABLA 'ordenes_lm' (NUEVA) ---
        if inspector.has_table('ordenes_lm'):
            orden_columns = {c['name'] for c in inspector.get_columns('ordenes_lm')}
            if 'status' not in orden_columns:
                print("La columna 'status' no existe en 'ordenes_lm'. Añadiéndola...")
                with engine.connect() as connection:
                    if connection.dialect.name == 'postgresql':
                        connection.execution_options(isolation_level="AUTOCOMMIT")
                    # Añade la columna con un valor por defecto para las filas existentes
                    connection.execute(text("ALTER TABLE ordenes_lm ADD COLUMN status VARCHAR(50) DEFAULT 'Pendiente' NOT NULL;"))
                    # Actualiza el valor por defecto por si acaso
                    connection.execute(text("ALTER TABLE ordenes_lm ALTER COLUMN status SET DEFAULT 'Pendiente';"))
                print("Columna 'status' añadida exitosamente.")

    except Exception as e:
        print(f"ERROR INESPERADO durante la inicialización de la BD: {e}", file=sys.stderr)


# --- (El resto de las funciones _execute_migration y create_default_admin no cambian) ---

def _execute_migration():
    print("Iniciando migración de datos de roles y turnos...")
    try:
        with engine.connect() as connection:
            if connection.dialect.name == 'postgresql':
                connection.execution_options(isolation_level="AUTOCOMMIT")
            with connection.begin():
                inspector = inspect(connection); user_columns = {c['name'] for c in inspector.get_columns('usuarios')}
                if 'role_id' not in user_columns: connection.execute(text("ALTER TABLE usuarios ADD COLUMN role_id INTEGER"))
                if 'turno_id' not in user_columns: connection.execute(text("ALTER TABLE usuarios ADD COLUMN turno_id INTEGER"))
                is_postgres = connection.dialect.name == 'postgresql'
                old_roles = connection.execute(text("SELECT DISTINCT role FROM usuarios WHERE role IS NOT NULL")).fetchall()
                for (role_name,) in old_roles:
                    if is_postgres: connection.execute(text("INSERT INTO roles (nombre) VALUES (:name) ON CONFLICT (nombre) DO NOTHING"), {"name": role_name})
                    else: connection.execute(text("INSERT OR IGNORE INTO roles (nombre) VALUES (:name)"), {"name": role_name})
                old_turnos = connection.execute(text("SELECT DISTINCT turno FROM usuarios WHERE turno IS NOT NULL")).fetchall()
                for (turno_name,) in old_turnos:
                    if is_postgres: connection.execute(text("INSERT INTO turnos (nombre) VALUES (:name) ON CONFLICT (nombre) DO NOTHING"), {"name": turno_name})
                    else: connection.execute(text("INSERT OR IGNORE INTO turnos (nombre) VALUES (:name)"), {"name": turno_name})
                connection.execute(text("UPDATE usuarios SET role_id = (SELECT id FROM roles WHERE nombre = usuarios.role)"))
                connection.execute(text("UPDATE usuarios SET turno_id = (SELECT id FROM turnos WHERE nombre = usuarios.turno)"))
                if 'role' in user_columns: connection.execute(text("ALTER TABLE usuarios DROP COLUMN role"))
                if 'turno' in user_columns: connection.execute(text("ALTER TABLE usuarios DROP COLUMN turno"))
                print("¡Migración completada exitosamente!")
    except Exception as e:
         print(f"ERROR CRÍTICO DURANTE LA MIGRACIÓN: {e}", file=sys.stderr)

def create_default_admin():
    print("Verificando la existencia del usuario administrador...")
    try:
        default_roles = ['ADMIN', 'IHP', 'FHP', 'PROGRAMA_LM']
        for role_name in default_roles:
            if not db_session.query(Rol).filter_by(nombre=role_name).first(): db_session.add(Rol(nombre=role_name))
        default_turnos = ['Turno A', 'Turno B', 'Turno C', 'N/A']
        for turno_name in default_turnos:
            if not db_session.query(Turno).filter_by(nombre=turno_name).first(): db_session.add(Turno(nombre=turno_name))
        db_session.commit()
        admin_role = db_session.query(Rol).filter_by(nombre='ADMIN').one_or_none()
        if not admin_role: print("ERROR CRÍTICO: El rol ADMIN no pudo ser creado o encontrado.", file=sys.stderr); return
        if not db_session.query(Usuario).filter(Usuario.role == admin_role).first():
            print("No se encontró usuario ADMIN. Creando usuario por defecto 'admin'...")
            na_turno = db_session.query(Turno).filter_by(nombre='N/A').one()
            default_admin = Usuario(username='admin', password='admin', role_id=admin_role.id, nombre_completo='Administrador del Sistema', cargo='Admin', turno_id=na_turno.id)
            db_session.add(default_admin)
            db_session.commit()
            print("Usuario 'admin' creado exitosamente.")
        else: print("El usuario administrador ya existe.")
    except Exception as e:
        db_session.rollback()
        print(f"ERROR al verificar/crear el usuario admin: {e}", file=sys.stderr)

if __name__ == '__main__':
    print("\n--- INICIANDO CONFIGURACIÓN MANUAL DE LA BASE DE DATOS ---")
    init_db(); create_default_admin(); db_session.remove()
    print("\n--- CONFIGURACIÓN MANUAL FINALIZADA ---")