import os
import sys
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, Date, Text, inspect, text, UniqueConstraint, Boolean, Table
from sqlalchemy.orm import sessionmaker, declarative_base, scoped_session, relationship
from sqlalchemy.exc import IntegrityError, OperationalError, ProgrammingError, NoSuchTableError
from werkzeug.security import generate_password_hash
from datetime import datetime

# --- Configuración de la Conexión a la BD (sin cambios) ---
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    if os.getenv('RENDER'):
        print("FATAL ERROR: La variable de entorno DATABASE_URL no está definida en el entorno de Render.", file=sys.stderr)
        sys.exit(1)
    else:
        print("ADVERTENCIA: DATABASE_URL no encontrada. Usando SQLite local.")
        project_root = os.path.dirname(os.path.abspath(__file__))
        instance_path = os.path.join(project_root, 'instance')
        os.makedirs(instance_path, exist_ok=True)
        db_path = os.path.join(instance_path, 'produccion.db')
        DATABASE_URL = f'sqlite:///{db_path}'
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
try:
    engine = create_engine(DATABASE_URL)
    db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))
except Exception as e:
    print(f"FATAL ERROR: No se pudo crear el motor de la BD: {e}", file=sys.stderr)
    sys.exit(1)
Base = declarative_base()
Base.query = db_session.query_property()

# --- MODELOS DE DATOS ACTUALIZADOS ---

# Tablas de asociación (sin cambios)
role_permissions = Table('role_permissions', Base.metadata,
    Column('role_id', Integer, ForeignKey('roles.id', ondelete='CASCADE'), primary_key=True),
    Column('permission_id', Integer, ForeignKey('permissions.id', ondelete='CASCADE'), primary_key=True)
)
role_viewable_roles = Table('role_viewable_roles', Base.metadata,
    Column('role_id', Integer, ForeignKey('roles.id', ondelete='CASCADE'), primary_key=True),
    Column('viewable_role_id', Integer, ForeignKey('roles.id', ondelete='CASCADE'), primary_key=True)
)

class Permission(Base):
    __tablename__ = 'permissions'
    id = Column(Integer, primary_key=True); name = Column(String(100), unique=True, nullable=False, index=True); description = Column(String(255))

class Rol(Base):
    __tablename__ = 'roles'
    id = Column(Integer, primary_key=True)
    nombre = Column(String(50), unique=True, nullable=False)
    permissions = relationship('Permission', secondary=role_permissions, backref='roles', lazy='subquery')
    viewable_roles = relationship('Rol', secondary=role_viewable_roles, primaryjoin=id == role_viewable_roles.c.role_id, secondaryjoin=id == role_viewable_roles.c.viewable_role_id, backref='viewed_by_roles')

class Turno(Base): __tablename__ = 'turnos'; id = Column(Integer, primary_key=True); nombre = Column(String(50), unique=True, nullable=False)
class Usuario(Base):
    __tablename__ = 'usuarios'
    id = Column(Integer, primary_key=True); username = Column(String(80), unique=True, nullable=False); password_hash = Column(String(256), nullable=False); nombre_completo = Column(String(120), nullable=True); cargo = Column(String(80), nullable=True); role_id = Column(Integer, ForeignKey('roles.id')); turno_id = Column(Integer, ForeignKey('turnos.id'))
    role = relationship('Rol', backref='usuarios'); turno = relationship('Turno', backref='usuarios')
    def __init__(self, username, password, role_id, nombre_completo=None, cargo=None, turno_id=None): self.username = username; self.password_hash = generate_password_hash(password); self.role_id = role_id; self.nombre_completo = nombre_completo; self.cargo = cargo; self.turno_id = turno_id

# --- MODELOS DE PROGRAMA LM ACTUALIZADOS ---
class OrdenLM(Base):
    __tablename__ = 'ordenes_lm'
    id = Column(Integer, primary_key=True)
    # numero_orden = Column(Integer, index=True) # <<< COLUMNA ELIMINADA
    wip_order = Column(String(100), unique=True, nullable=False)
    item = Column(String(100))
    qty = Column(Integer, nullable=False, default=1)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True) # <<< Se añade index=True para mejor rendimiento al ordenar
    status = Column(String(50), default='Pendiente', nullable=False, index=True)
    celdas = relationship('DatoCeldaLM', backref='orden', cascade='all, delete-orphan')

class ColumnaLM(Base):
    __tablename__ = 'columnas_lm'
    id = Column(Integer, primary_key=True)
    nombre = Column(String(100), unique=True, nullable=False)
    orden = Column(Integer, default=100)
    editable_por_lm = Column(Boolean, default=True, nullable=False)
    ancho_columna = Column(Integer, default=180) 
    celdas = relationship('DatoCeldaLM', backref='columna', cascade='all, delete-orphan')

class DatoCeldaLM(Base):
    __tablename__ = 'datos_celda_lm'
    id = Column(Integer, primary_key=True)
    orden_id = Column(Integer, ForeignKey('ordenes_lm.id', ondelete='CASCADE'), nullable=False)
    columna_id = Column(Integer, ForeignKey('columnas_lm.id', ondelete='CASCADE'), nullable=False)
    valor = Column(Text)
    estilos_css = Column(Text, nullable=True)
    __table_args__ = (UniqueConstraint('orden_id', 'columna_id', name='_orden_columna_uc'),)

# --- Otros modelos (sin cambios) ---
class Pronostico(Base): __tablename__ = 'pronosticos'; id = Column(Integer, primary_key=True); fecha = Column(Date, nullable=False, index=True); grupo = Column(String(10), nullable=False, index=True); area = Column(String(50), nullable=False); turno = Column(String(20), nullable=False); valor_pronostico = Column(Integer); razon_desviacion = Column(Text); usuario_razon = Column(String(80)); fecha_razon = Column(DateTime); status = Column(String(50), default='Nuevo', index=True); __table_args__ = (UniqueConstraint('fecha', 'grupo', 'area', 'turno', name='_fecha_grupo_area_turno_uc'),)
class ProduccionCaptura(Base): __tablename__ = 'produccion_capturas'; id = Column(Integer, primary_key=True); fecha = Column(Date, nullable=False, index=True); grupo = Column(String(10), nullable=False, index=True); area = Column(String(50), nullable=False); hora = Column(String(10), nullable=False); valor_producido = Column(Integer); usuario_captura = Column(String(80)); fecha_captura = Column(DateTime, default=datetime.utcnow); __table_args__ = (UniqueConstraint('fecha', 'grupo', 'area', 'hora', name='_fecha_grupo_area_hora_uc'),)
class ActivityLog(Base): __tablename__ = 'activity_logs'; id = Column(Integer, primary_key=True); timestamp = Column(DateTime, default=datetime.utcnow, index=True); username = Column(String(80), index=True); action = Column(String(255)); details = Column(Text); area_grupo = Column(String(50), index=True); ip_address = Column(String(45)); category = Column(String(50)); severity = Column(String(20))
class OutputData(Base): __tablename__ = 'output_data'; id = Column(Integer, primary_key=True); fecha = Column(Date, nullable=False, index=True); grupo = Column(String(10), nullable=False, index=True); pronostico = Column(Integer); output = Column(Integer); usuario_captura = Column(String(80)); fecha_captura = Column(DateTime, default=datetime.utcnow)
class SolicitudCorreccion(Base): __tablename__ = 'solicitudes_correccion'; id = Column(Integer, primary_key=True); timestamp = Column(DateTime, default=datetime.utcnow, index=True); usuario_solicitante = Column(String(80), nullable=False); fecha_problema = Column(Date, nullable=False); grupo = Column(String(10), nullable=False); area = Column(String(50)); turno = Column(String(20)); tipo_error = Column(String(100), nullable=False); descripcion = Column(Text, nullable=False); status = Column(String(50), default='Pendiente', index=True); admin_username = Column(String(80)); fecha_resolucion = Column(DateTime); admin_notas = Column(Text)

def init_db():
    """Crea todas las tablas y ejecuta migraciones automáticas si es necesario."""
    print("Verificando y creando tablas si es necesario...")
    Base.metadata.create_all(bind=engine)
    print("Verificación de tablas completada.")

    # --- LÓGICA DE MIGRACIÓN AUTOMÁTICA ---
    inspector = inspect(engine)
    try:
        # Añadir columna 'ancho_columna' si no existe
        if inspector.has_table('columnas_lm') and 'ancho_columna' not in {c['name'] for c in inspector.get_columns('columnas_lm')}:
            print("MIGRACIÓN: Añadiendo columna 'ancho_columna' a la tabla 'columnas_lm'...")
            with engine.connect() as connection:
                if connection.dialect.name == 'postgresql': connection.execution_options(isolation_level="AUTOCOMMIT")
                connection.execute(text("ALTER TABLE columnas_lm ADD COLUMN ancho_columna INTEGER DEFAULT 180;"))
            print("Columna 'ancho_columna' añadida exitosamente.")
    except Exception as e:
        print(f"ERROR durante la migración automática de columnas de Programa LM: {e}", file=sys.stderr)

def create_default_admin():
    print("Iniciando verificación y creación de datos por defecto...")
    try:
        # --- (Creación de roles, permisos y asignaciones - Sin cambios, ya está correcto) ---
        default_roles = ['ADMIN', 'IHP', 'FHP', 'PROGRAMA_LM', 'ARTISAN']
        for role_name in default_roles:
            if not db_session.query(Rol).filter_by(nombre=role_name).first(): db_session.add(Rol(nombre=role_name))
        default_turnos = ['Turno A', 'Turno B', 'Turno C', 'N/A']
        for turno_name in default_turnos:
            if not db_session.query(Turno).filter_by(nombre=turno_name).first(): db_session.add(Turno(nombre=turno_name))
        db_session.commit()
        DEFAULT_PERMISSIONS = {
            'admin.access': 'Acceso global a todas las funciones.', 'dashboard.view.admin': 'Ver el dashboard de administrador.', 'dashboard.view.group': 'Ver dashboards de grupo (IHP/FHP).',
            'captura.access': 'Acceder a las páginas de captura.', 'registro.view': 'Ver las páginas de registro de producción.', 'reportes.view': 'Ver la página de reportes.',
            'programa_lm.view': 'Ver el programa LM.', 'programa_lm.edit': 'Editar celdas y estado en programa LM.', 'programa_lm.admin': 'Administrar filas/columnas del programa LM.',
            'users.manage': 'Gestionar usuarios (crear, editar, eliminar).', 'roles.manage': 'Gestionar roles y sus permisos.', 'logs.view': 'Ver el log de actividad del sistema.', 'actions.center': 'Gestionar el centro de acciones.',
            'borrado.maestro': 'Permiso único para el borrado masivo de datos, por encima del Admin.'
        }
        for name, desc in DEFAULT_PERMISSIONS.items():
            if not db_session.query(Permission).filter_by(name=name).first(): db_session.add(Permission(name=name, description=desc))
        db_session.commit()
        admin_perms = [p for p in DEFAULT_PERMISSIONS.keys() if p != 'borrado.maestro']
        artisan_perms = list(DEFAULT_PERMISSIONS.keys())
        PERMISSIONS_FOR_ROLE = {
            'ADMIN': admin_perms, 'IHP': ['dashboard.view.group', 'captura.access', 'registro.view', 'reportes.view'],
            'FHP': ['dashboard.view.group', 'captura.access', 'registro.view', 'reportes.view'], 'PROGRAMA_LM': ['programa_lm.view', 'programa_lm.edit'],
            'ARTISAN': artisan_perms
        }
        for role_name, perm_names in PERMISSIONS_FOR_ROLE.items():
            role = db_session.query(Rol).filter_by(nombre=role_name).one_or_none();
            if role:
                role.permissions.clear();
                for perm_name in perm_names:
                    perm = db_session.query(Permission).filter_by(name=perm_name).one(); role.permissions.append(perm)
        db_session.commit()
        print("Configurando visibilidad de roles por defecto...")
        all_roles_q = db_session.query(Rol).all()
        admin_role = next((r for r in all_roles_q if r.nombre == 'ADMIN'), None)
        artisan_role = next((r for r in all_roles_q if r.nombre == 'ARTISAN'), None)
        for role in all_roles_q:
            if role not in role.viewable_roles: role.viewable_roles.append(role)
            if admin_role and role not in admin_role.viewable_roles: admin_role.viewable_roles.append(role)
            if artisan_role and role not in artisan_role.viewable_roles: artisan_role.viewable_roles.append(role)
        db_session.commit()
        print("Visibilidad por defecto configurada.")
        
        # =========================================================================
        # ========= LÓGICA DE CREACIÓN/ACTUALIZACIÓN DE USUARIOS (CORREGIDA) ========
        # =========================================================================
        na_turno = db_session.query(Turno).filter_by(nombre='N/A').one_or_none()
        
        # 1. Crear usuario ADMIN genérico si no existe ninguno
        if admin_role and not db_session.query(Usuario).filter_by(role_id=admin_role.id).first():
            # Evitar crear 'admin' si ya existe con otro rol
            if not db_session.query(Usuario).filter_by(username='admin').first():
                print("No se encontró usuario ADMIN. Creando usuario 'admin' por defecto...")
                default_admin = Usuario(username='admin', password='password', role_id=admin_role.id, nombre_completo='Administrador', cargo='System Admin', turno_id=na_turno.id if na_turno else None)
                db_session.add(default_admin)
                print("Usuario 'admin' creado.")
        
        # 2. Lógica robusta para el usuario ARTISAN ('GCL1909')
        if artisan_role:
            user_gcl1909 = db_session.query(Usuario).filter_by(username='GCL1909').first()

            if user_gcl1909:
                # Si el usuario existe, nos aseguramos de que tenga el rol correcto
                if user_gcl1909.role_id != artisan_role.id:
                    print("Usuario 'GCL1909' encontrado. Actualizando su rol a ARTISAN.")
                    user_gcl1909.role_id = artisan_role.id
                else:
                    print("Usuario 'GCL1909' ya tiene el rol ARTISAN. No se necesitan cambios.")
            else:
                # Si el usuario no existe, lo creamos
                print("Usuario 'GCL1909' no encontrado. Creándolo con el rol ARTISAN...")
                default_artisan = Usuario(
                    username='GCL1909', 
                    password='1909', 
                    role_id=artisan_role.id,
                    nombre_completo='Usuario Maestro', 
                    cargo='Artisan', 
                    turno_id=na_turno.id if na_turno else None
                )
                db_session.add(default_artisan)
                print("Usuario 'GCL1909' creado con rol ARTISAN.")
            
        db_session.commit()
        print("Verificación de usuarios por defecto completada.")

    except Exception as e:
        db_session.rollback()
        print(f"ERROR al inicializar la base de datos: {e}", file=sys.stderr)
        raise
    
if __name__ == '__main__':
    init_db(); create_default_admin(); db_session.remove()