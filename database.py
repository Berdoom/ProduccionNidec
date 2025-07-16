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


# --- MODELOS DE DATOS CON PERMISOS ---

# Tabla de asociación para la relación muchos-a-muchos entre roles y permisos
role_permissions = Table('role_permissions', Base.metadata,
    Column('role_id', Integer, ForeignKey('roles.id', ondelete='CASCADE'), primary_key=True),
    Column('permission_id', Integer, ForeignKey('permissions.id', ondelete='CASCADE'), primary_key=True)
)

class Permission(Base):
    """Define un permiso específico en el sistema."""
    __tablename__ = 'permissions'
    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True, nullable=False, index=True) # ej: 'users.manage'
    description = Column(String(255))

class Rol(Base):
    """Rol de usuario, ahora con una relación a sus permisos."""
    __tablename__ = 'roles'
    id = Column(Integer, primary_key=True)
    nombre = Column(String(50), unique=True, nullable=False)
    # Relación para obtener fácilmente los permisos de un rol
    permissions = relationship('Permission', secondary=role_permissions, backref='roles', lazy='subquery')

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

# --- Otros modelos (sin cambios en su estructura) ---
class Pronostico(Base): __tablename__ = 'pronosticos'; id = Column(Integer, primary_key=True); fecha = Column(Date, nullable=False, index=True); grupo = Column(String(10), nullable=False, index=True); area = Column(String(50), nullable=False); turno = Column(String(20), nullable=False); valor_pronostico = Column(Integer); razon_desviacion = Column(Text); usuario_razon = Column(String(80)); fecha_razon = Column(DateTime); status = Column(String(50), default='Nuevo', index=True); __table_args__ = (UniqueConstraint('fecha', 'grupo', 'area', 'turno', name='_fecha_grupo_area_turno_uc'),)
class ProduccionCaptura(Base): __tablename__ = 'produccion_capturas'; id = Column(Integer, primary_key=True); fecha = Column(Date, nullable=False, index=True); grupo = Column(String(10), nullable=False, index=True); area = Column(String(50), nullable=False); hora = Column(String(10), nullable=False); valor_producido = Column(Integer); usuario_captura = Column(String(80)); fecha_captura = Column(DateTime, default=datetime.utcnow); __table_args__ = (UniqueConstraint('fecha', 'grupo', 'area', 'hora', name='_fecha_grupo_area_hora_uc'),)
class ActivityLog(Base): __tablename__ = 'activity_logs'; id = Column(Integer, primary_key=True); timestamp = Column(DateTime, default=datetime.utcnow, index=True); username = Column(String(80), index=True); action = Column(String(255)); details = Column(Text); area_grupo = Column(String(50), index=True); ip_address = Column(String(45)); category = Column(String(50)); severity = Column(String(20))
class OutputData(Base): __tablename__ = 'output_data'; id = Column(Integer, primary_key=True); fecha = Column(Date, nullable=False, index=True); grupo = Column(String(10), nullable=False, index=True); pronostico = Column(Integer); output = Column(Integer); usuario_captura = Column(String(80)); fecha_captura = Column(DateTime, default=datetime.utcnow)
class SolicitudCorreccion(Base): __tablename__ = 'solicitudes_correccion'; id = Column(Integer, primary_key=True); timestamp = Column(DateTime, default=datetime.utcnow, index=True); usuario_solicitante = Column(String(80), nullable=False); fecha_problema = Column(Date, nullable=False); grupo = Column(String(10), nullable=False); area = Column(String(50)); turno = Column(String(20)); tipo_error = Column(String(100), nullable=False); descripcion = Column(Text, nullable=False); status = Column(String(50), default='Pendiente', index=True); admin_username = Column(String(80)); fecha_resolucion = Column(DateTime); admin_notas = Column(Text)
class OrdenLM(Base): __tablename__ = 'ordenes_lm'; id = Column(Integer, primary_key=True); wip_order = Column(String(100), unique=True, nullable=False); item = Column(String(100)); qty = Column(Integer, nullable=False, default=1); timestamp = Column(DateTime, default=datetime.utcnow); celdas = relationship('DatoCeldaLM', backref='orden', cascade='all, delete-orphan'); status = Column(String(50), default='Pendiente', nullable=False, index=True)
class ColumnaLM(Base): __tablename__ = 'columnas_lm'; id = Column(Integer, primary_key=True); nombre = Column(String(100), unique=True, nullable=False); orden = Column(Integer, default=100); editable_por_lm = Column(Boolean, default=True, nullable=False); celdas = relationship('DatoCeldaLM', backref='columna', cascade='all, delete-orphan')
class DatoCeldaLM(Base): __tablename__ = 'datos_celda_lm'; id = Column(Integer, primary_key=True); orden_id = Column(Integer, ForeignKey('ordenes_lm.id', ondelete='CASCADE'), nullable=False); columna_id = Column(Integer, ForeignKey('columnas_lm.id', ondelete='CASCADE'), nullable=False); valor = Column(Text); estilos_css = Column(Text, nullable=True); __table_args__ = (UniqueConstraint('orden_id', 'columna_id', name='_orden_columna_uc'),)


def init_db():
    """Crea todas las tablas en la base de datos si no existen."""
    print("Verificando y creando tablas si es necesario...")
    # Crea todas las tablas definidas en los modelos de SQLAlchemy
    Base.metadata.create_all(bind=engine)
    print("Verificación de tablas completada.")

# --- Versión explicativa y resumida de la migración ---
def create_default_admin():
    """
    Función de inicialización robusta que realiza la migración.
    PASO 1: Asegura que los roles y turnos base existan.
    PASO 2: Crea la lista de todos los nuevos permisos.
    PASO 3: Asigna automáticamente los permisos a los roles existentes.
    PASO 4: Crea el nuevo usuario administrador si no existe.
    """
    print("Iniciando verificación y creación de datos por defecto...")
    try:
        # 1. Crear roles y turnos por defecto
        default_roles = ['ADMIN', 'IHP', 'FHP', 'PROGRAMA_LM']
        for role_name in default_roles:
            if not db_session.query(Rol).filter_by(nombre=role_name).first():
                db_session.add(Rol(nombre=role_name))
        
        default_turnos = ['Turno A', 'Turno B', 'Turno C', 'N/A']
        for turno_name in default_turnos:
            if not db_session.query(Turno).filter_by(nombre=turno_name).first():
                db_session.add(Turno(nombre=turno_name))
        db_session.commit()

        # 2. Definir y crear todos los permisos del sistema
        DEFAULT_PERMISSIONS = {
            'admin.access': 'Acceso global a todas las funciones.',
            'dashboard.view.admin': 'Ver el dashboard de administrador.',
            'dashboard.view.group': 'Ver dashboards de grupo (IHP/FHP).',
            'captura.access': 'Acceder a las páginas de captura.',
            'registro.view': 'Ver las páginas de registro de producción.',
            'reportes.view': 'Ver la página de reportes.',
            'programa_lm.view': 'Ver el programa LM.',
            'programa_lm.edit': 'Editar celdas y estado en programa LM.',
            'programa_lm.admin': 'Administrar filas/columnas del programa LM.',
            'users.manage': 'Gestionar usuarios (crear, editar, eliminar).',
            'roles.manage': 'Gestionar roles y sus permisos.',
            'logs.view': 'Ver el log de actividad del sistema.',
            'actions.center': 'Gestionar el centro de acciones.'
        }
        for name, desc in DEFAULT_PERMISSIONS.items():
            if not db_session.query(Permission).filter_by(name=name).first():
                db_session.add(Permission(name=name, description=desc))
        db_session.commit()

        # 3. Asignar permisos a los roles por defecto
        PERMISSIONS_FOR_ROLE = {
            'ADMIN': list(DEFAULT_PERMISSIONS.keys()),
            'IHP': ['dashboard.view.group', 'captura.access', 'registro.view', 'reportes.view'],
            'FHP': ['dashboard.view.group', 'captura.access', 'registro.view', 'reportes.view'],
            'PROGRAMA_LM': ['programa_lm.view', 'programa_lm.edit']
        }
        for role_name, perm_names in PERMISSIONS_FOR_ROLE.items():
            role = db_session.query(Rol).filter_by(nombre=role_name).one_or_none()
            if role:
                current_perms = {p.name for p in role.permissions}
                for perm_name in perm_names:
                    if perm_name not in current_perms:
                        perm = db_session.query(Permission).filter_by(name=perm_name).one()
                        role.permissions.append(perm)
        db_session.commit()
        print("Permisos por defecto creados y asignados.")

        # 4. Corregir usuarios existentes sin turno asignado
        na_turno = db_session.query(Turno).filter_by(nombre='N/A').one_or_none()
        if na_turno:
            usuarios_sin_turno = db_session.query(Usuario).filter(Usuario.turno_id.is_(None)).all()
            if usuarios_sin_turno:
                print(f"Detectados {len(usuarios_sin_turno)} usuarios sin turno. Asignando 'N/A'...")
                for user in usuarios_sin_turno: user.turno_id = na_turno.id
                db_session.commit()

        # 5. Crear el usuario administrador por defecto si no existe
        admin_role = db_session.query(Rol).filter_by(nombre='ADMIN').one()
        if not db_session.query(Usuario).filter(Usuario.role_id == admin_role.id).first():
            print("No se encontró usuario ADMIN. Creando usuario 'GCL1909' por defecto...")
            na_turno_admin = db_session.query(Turno).filter_by(nombre='N/A').one()
            default_admin = Usuario(
                username='GCL1909',
                password='1909',
                role_id=admin_role.id,
                nombre_completo='software',
                cargo='System Administrator',
                turno_id=na_turno_admin.id
            )
            db_session.add(default_admin)
            db_session.commit()
            print("Usuario 'GCL1909' creado. ¡LA CONTRASEÑA ES INSEGURA! Se recomienda cambiarla.")
        else:
            print("El usuario administrador ya existe.")

    except Exception as e:
        db_session.rollback()
        print(f"ERROR CRÍTICO durante la inicialización de la BD: {e}", file=sys.stderr)
        # Es importante relanzar el error si es grave para detener la aplicación
        raise

if __name__ == '__main__':
    print("\n--- INICIANDO CONFIGURACIÓN MANUAL DE LA BASE DE DATOS ---")
    init_db()
    create_default_admin()
    db_session.remove()
    print("\n--- CONFIGURACIÓN MANUAL FINALIZADA ---")