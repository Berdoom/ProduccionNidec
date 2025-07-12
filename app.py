import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file, abort
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import pandas as pd
import io
from functools import wraps
import locale
from collections import Counter
import calendar
from flask_apscheduler import APScheduler
# --- NUEVO: Importar zoneinfo para zona horaria de México ---
try:
    from zoneinfo import ZoneInfo
except ImportError:
    from pytz import timezone as ZoneInfo  # fallback para Python <3.9

# --- Importaciones de la Base de Datos y Correo ---
from sqlalchemy import func, exc, extract
from database import db_session, Usuario, Pronostico, ProduccionCaptura, ActivityLog, OutputData, SolicitudCorreccion, init_db, create_default_admin
from mail_sender import send_email

# --- Configurar locale para español (para nombres de meses y días) ---
try:
    locale.setlocale(locale.LC_TIME, 'es_ES.UTF-8')
except locale.Error:
    try:
        locale.setlocale(locale.LC_TIME, 'Spanish_Spain')
    except locale.Error:
        print("Locale 'es_ES' no encontrado, usando el default.")

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "n1D3c$#pro")

# ======================================================================
# --- CONFIGURACIÓN DEL SISTEMA DE NOTIFICACIONES PROGRAMADAS ---
# ======================================================================
scheduler = APScheduler()

# --- NUEVA FUNCIÓN: Fecha y hora de México ---
def now_mexico():
    try:
        return datetime.now(ZoneInfo("America/Mexico_City"))
    except Exception:
        # fallback si zoneinfo falla
        import pytz
        return datetime.now(pytz.timezone("America/Mexico_City"))

# --- NUEVA FUNCIÓN: Obtener la fecha del día operativo ---
def get_business_date():
    """
    Determina la fecha del "día operativo".
    El día cambia a las 7:30 AM. Antes de esa hora, se considera el día anterior.
    """
    now = now_mexico()
    # Si la hora actual es antes de las 7:30 AM, consideramos que es el día operativo anterior.
    if now.hour < 7 or (now.hour == 7 and now.minute < 30):
        return (now - timedelta(days=1)).date()
    return now.date()

def check_and_send_notifications():
    with app.app_context():
        print(f"[{now_mexico()}] TAREA PROGRAMADA: Verificando datos de producción faltantes...")
        today = now_mexico().date()
        now = now_mexico()
        missing_entries = []
        all_areas = list(set([a for a in AREAS_IHP if a != 'Output'] + [a for a in AREAS_FHP if a != 'Output']))
        for turno, horas in HORAS_TURNO.items():
            for hora_str in horas:
                try:
                    hora_obj = datetime.strptime(hora_str, '%I%p').time()
                    target_datetime = datetime.combine(today, hora_obj)
                except ValueError: continue
                if (target_datetime + timedelta(hours=1)) < now < (target_datetime + timedelta(hours=3)):
                    for area in all_areas:
                        grupo = 'IHP' if area in AREAS_IHP else 'FHP'
                        entry_exists = db_session.query(ProduccionCaptura).filter(ProduccionCaptura.fecha == today, ProduccionCaptura.grupo == grupo, ProduccionCaptura.area == area, ProduccionCaptura.hora == hora_str).first()
                        if not entry_exists:
                            missing_info = f"- Grupo {grupo}, Área: {area}, Hora: {hora_str}"
                            missing_entries.append(missing_info)
        if missing_entries:
            print(f"¡Se encontraron {len(missing_entries)} registros faltantes! Preparando para enviar correo.")
            recipient = os.getenv('MAIL_RECIPIENT')
            subject = f"Alerta: Faltan Registros de Producción ({datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC)"
            body_html = "<p>Se ha detectado que los siguientes registros de producción no han sido capturados a tiempo:</p><ul>"
            for item in missing_entries: body_html += f"<li>{item}</li>"
            body_html += "</ul><p>Por favor, acceda al sistema para completar la información.</p>"
            send_email(recipient, subject, body_html)
        else:
            print(f"[{datetime.utcnow()}] TAREA PROGRAMADA: No se encontraron registros faltantes.")

# --- INICIALIZACIÓN DE LA BASE DE DATOS Y DEL PROGRAMADOR ---
print("INICIANDO APLICACIÓN FLASK...")
with app.app_context():
    print("Ejecutando inicialización de la base de datos...")
    init_db()
    create_default_admin()
    print("Inicialización de la base de datos completada.")
    if not scheduler.running:
        scheduler.init_app(app)
        scheduler.add_job(id='check_production_job', func=check_and_send_notifications, trigger='interval', minutes=5)
        scheduler.start()
        print("Sistema de notificaciones programadas iniciado.")

app.permanent_session_lifetime = timedelta(minutes=30)

@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()

@app.before_request
def before_request_handler():
    session.permanent = True

# --- Constantes y Funciones de Utilidad ---
AREAS_IHP = ['Soporte', 'Servicio', 'Cuerpos', 'Flechas', 'Misceláneos', 'Embobinado', 'ECC', 'ERF', 'Carga', 'Output']
AREAS_FHP = ['Rotores Inyección', 'Rotores ERF', 'Cuerpos', 'Flechas', 'Embobinado', 'Barniz', 'Soporte', 'Pintura', 'Carga', 'Output']
HORAS_TURNO = { 'Turno A': ['10AM', '1PM', '4PM'], 'Turno B': ['7PM', '10PM', '12AM'], 'Turno C': ['3AM', '6AM'] }
NOMBRES_TURNOS = list(HORAS_TURNO.keys())

def to_slug(text):
    return text.replace(' ', '_').replace('.', '').replace('/', '')

app.jinja_env.filters['slug'] = to_slug

def get_month_name(month_number):
    try: return calendar.month_name[int(month_number)]
    except (IndexError, ValueError): return ''

app.jinja_env.filters['month_name'] = get_month_name

def log_activity(action, details="", area_grupo=None, category="General", severity="Info"):
    try:
        log_entry = ActivityLog(
            timestamp=datetime.utcnow(),
            username=session.get('username', 'Sistema'),
            action=action,
            details=details,
            area_grupo=area_grupo,
            ip_address=request.remote_addr,
            category=category,
            severity=severity
        )
        db_session.add(log_entry)
    except exc.SQLAlchemyError as e:
        db_session.rollback()
        print(f"Error al registrar actividad: {e}")

# --- Decoradores ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'loggedin' not in session:
            flash('Debes iniciar sesión para acceder a esta página. Tu sesión puede haber expirado.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('role') not in allowed_roles:
                flash('No tienes permiso para acceder a esta página.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def csrf_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == "POST":
            token = request.form.get("csrf_token") or (request.is_json and request.json.get("csrf_token"))
            if not token or token != session.get("csrf_token"):
                flash("Error de seguridad (CSRF Token inválido). Inténtalo de nuevo.", "danger")
                if request.is_json: return jsonify({'status': 'error', 'message': 'CSRF token missing or incorrect'}), 403
                return redirect(request.url)
        return f(*args, **kwargs)
    return decorated_function

# --- Rutas de Autenticación y Navegación Principal ---
@app.route('/', methods=['GET', 'POST'])
@csrf_required
def login():
    if 'loggedin' in session: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = db_session.query(Usuario).filter(Usuario.username == username).first()
        if user and check_password_hash(user.password_hash, password):
            session.clear()
            session.permanent = True
            session['loggedin'] = True
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            session['nombre_completo'] = user.nombre_completo
            session['csrf_token'] = secrets.token_hex(16)
            log_activity("Inicio de sesión", f"Rol: {user.role}", 'Sistema', 'Autenticación', 'Info')
            db_session.commit()
            return redirect(url_for('dashboard'))
        else:
            log_activity("Intento de inicio de sesión fallido", f"Intento con usuario: '{username}'", 'Sistema', 'Seguridad', 'Warning')
            db_session.commit()
            flash('Usuario o contraseña incorrectos.', 'danger')
    if 'csrf_token' not in session: session['csrf_token'] = secrets.token_hex(16)
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_activity("Cierre de sesión", "", 'Sistema', 'Autenticación', 'Info')
    db_session.commit()
    session.clear()
    flash('Has cerrado sesión correctamente.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    role = session.get('role')
    if role in ['IHP', 'FHP']: return redirect(url_for('dashboard_group', group=role.lower()))
    if role == 'ADMIN': return redirect(url_for('dashboard_admin'))
    return redirect(url_for('login'))

# --- Funciones de Lógica de Negocio ---
def get_performance_data_from_db(group, date_str):
    selected_date = datetime.strptime(date_str, '%Y-%m-%d').date()
    areas = [area for area in (AREAS_IHP if group == 'IHP' else AREAS_FHP) if area != 'Output']
    performance_data = {area: {turno: {'pronostico': 0, 'producido': 0} for turno in NOMBRES_TURNOS} for area in areas}
    try:
        pronosticos = db_session.query(Pronostico.area, Pronostico.turno, Pronostico.valor_pronostico).filter(Pronostico.fecha == selected_date, Pronostico.grupo == group).all()
        for area, turno, valor in pronosticos:
            if area in performance_data and turno in performance_data[area]:
                performance_data[area][turno]['pronostico'] = valor or 0
        produccion_rows = db_session.query(ProduccionCaptura.area, ProduccionCaptura.hora, ProduccionCaptura.valor_producido).filter(ProduccionCaptura.fecha == selected_date, ProduccionCaptura.grupo == group).all()
        for area, hora, valor in produccion_rows:
            for turno, horas in HORAS_TURNO.items():
                if hora in horas:
                    if area in performance_data and turno in performance_data[area]:
                        performance_data[area][turno]['producido'] += valor or 0
                    break
    except exc.SQLAlchemyError as e:
        flash(f"Error al consultar datos de rendimiento: {e}", "danger")
    return performance_data

def get_group_performance(group_name, start_date_str, end_date_str=None):
    start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
    end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date() if end_date_str else start_date
    try:
        query_pronostico_areas = db_session.query(func.sum(Pronostico.valor_pronostico)).filter(Pronostico.grupo == group_name, Pronostico.fecha.between(start_date, end_date))
        total_pronostico_areas = query_pronostico_areas.scalar() or 0
        
        query_pronostico_output = db_session.query(func.sum(OutputData.pronostico)).filter(OutputData.grupo == group_name, OutputData.fecha.between(start_date, end_date))
        total_pronostico_output = query_pronostico_output.scalar() or 0

        query_producido_areas = db_session.query(func.sum(ProduccionCaptura.valor_producido)).filter(ProduccionCaptura.grupo == group_name, ProduccionCaptura.fecha.between(start_date, end_date))
        total_producido_areas = query_producido_areas.scalar() or 0
        
        query_producido_output = db_session.query(func.sum(OutputData.output)).filter(OutputData.grupo == group_name, OutputData.fecha.between(start_date, end_date))
        total_producido_output = query_producido_output.scalar() or 0

        total_pronostico = total_pronostico_areas + total_pronostico_output
        total_producido = total_producido_areas + total_producido_output

        eficiencia = (total_producido / total_pronostico * 100) if total_pronostico > 0 else 0
        return {'pronostico': f"{total_pronostico:,.0f}", 'producido': f"{total_producido:,.0f}", 'eficiencia': round(eficiencia, 2)}
    except exc.SQLAlchemyError as e:
        flash(f"Error al calcular el rendimiento del grupo: {e}", "danger")
        return {'pronostico': '0', 'producido': '0', 'eficiencia': 0}

def get_structured_capture_data(group_name, selected_date):
    data_to_render = {}
    try:
        areas_list = AREAS_IHP if group_name == 'IHP' else AREAS_FHP
        for area in areas_list:
            if area == 'Output': continue
            data_to_render[area] = {}
            for turno in NOMBRES_TURNOS:
                data_to_render[area][turno] = { 'pronostico': '', 'razon_desviacion': None }
                for hora in HORAS_TURNO[turno]:
                    data_to_render[area][turno][hora] = ''
        all_pronosticos = db_session.query(Pronostico).filter_by(fecha=selected_date, grupo=group_name).all()
        all_produccion = db_session.query(ProduccionCaptura).filter_by(fecha=selected_date, grupo=group_name).all()
        for p in all_pronosticos:
            if p.area in data_to_render and p.turno in data_to_render[p.area]:
                data_to_render[p.area][p.turno]['pronostico'] = p.valor_pronostico
                data_to_render[p.area][p.turno]['razon_desviacion'] = p.razon_desviacion
        for prod in all_produccion:
            for turno, horas in HORAS_TURNO.items():
                if prod.hora in horas:
                    if prod.area in data_to_render and turno in data_to_render[prod.area]:
                        data_to_render[prod.area][turno][prod.hora] = prod.valor_producido
                    break
    except exc.SQLAlchemyError as e:
        flash(f"Error al obtener datos estructurados para captura: {e}", "danger")
    return data_to_render

def get_output_data(group, date_str):
    selected_date = datetime.strptime(date_str, '%Y-%m-%d').date()
    try:
        output_row = db_session.query(OutputData).filter_by(fecha=selected_date, grupo=group).first()
        if output_row: return {'pronostico': output_row.pronostico or 0, 'output': output_row.output or 0}
    except exc.SQLAlchemyError as e:
        flash(f"Error al obtener datos de Output: {e}", "danger")
    return {'pronostico': 0, 'output': 0}

def get_heatmap_color_class(eficiencia):
    if eficiencia == 0: return 'heatmap-zero'
    if eficiencia < 80: return 'heatmap-danger'
    if eficiencia < 95: return 'heatmap-warning'
    if eficiencia <= 105: return 'heatmap-success'
    return 'heatmap-excellent'

app.jinja_env.filters['heatmap_color'] = get_heatmap_color_class

def get_heatmap_badge_class(eficiencia):
    if eficiencia == 0: return 'badge-secondary'
    if eficiencia < 80: return 'badge-danger'
    if eficiencia < 95: return 'badge-warning'
    if eficiencia <= 105: return 'badge-success'
    return 'badge-nidec'

app.jinja_env.filters['heatmap_color_badge'] = get_heatmap_badge_class

def get_detailed_performance_data(selected_date):
    performance_data = {'IHP': {}, 'FHP': {}}
    all_areas = {'IHP': AREAS_IHP, 'FHP': AREAS_FHP}

    try:
        pronosticos = db_session.query(Pronostico).filter(Pronostico.fecha == selected_date).all()
        produccion_horas = db_session.query(ProduccionCaptura).filter(ProduccionCaptura.fecha == selected_date).all()

        for group, areas in all_areas.items():
            for area in [a for a in areas if a != 'Output']:
                performance_data[group][area] = {}
                for turno in NOMBRES_TURNOS:
                    performance_data[group][area][turno] = {
                        'pronostico': 0,
                        'producido': 0,
                        'eficiencia': 0,
                        'horas': {hora: 0 for hora in HORAS_TURNO[turno]}
                    }
        
        for p in pronosticos:
            group_key = p.grupo.upper()
            if group_key in performance_data and p.area in performance_data[group_key]:
                performance_data[group_key][p.area][p.turno]['pronostico'] = p.valor_pronostico or 0
        
        for prod in produccion_horas:
            group_key = prod.grupo.upper()
            for turno, horas_del_turno in HORAS_TURNO.items():
                if prod.hora in horas_del_turno:
                    if group_key in performance_data and prod.area in performance_data[group_key]:
                        performance_data[group_key][prod.area][turno]['horas'][prod.hora] = prod.valor_producido or 0
                        performance_data[group_key][prod.area][turno]['producido'] += prod.valor_producido or 0
                    break
        
        for group in performance_data:
            for area in performance_data[group]:
                for turno in performance_data[group][area]:
                    turno_data = performance_data[group][area][turno]
                    if turno_data['pronostico'] > 0:
                        turno_data['eficiencia'] = round((turno_data['producido'] / turno_data['pronostico']) * 100, 1)

    except exc.SQLAlchemyError as e:
        flash(f"Error al generar datos detallados del dashboard: {e}", "danger")

    return performance_data


# --- Rutas de Dashboards y Registros ---
@app.route('/dashboard/admin')
@login_required
@role_required(['ADMIN'])
def dashboard_admin():
    selected_date_str = request.args.get('fecha', get_business_date().strftime('%Y-%m-%d'))
    try:
        selected_date = datetime.strptime(selected_date_str, '%Y-%m-%d').date()
    except ValueError:
        selected_date = get_business_date()
        selected_date_str = selected_date.strftime('%Y-%m-%d')
        flash("Formato de fecha inválido. Mostrando datos del día operativo actual.", "warning")

    # 1. Obtener todos los datos detallados de una vez
    performance_data = get_detailed_performance_data(selected_date)
    
    # 2. Añadir datos de output a la estructura principal
    output_data_ihp = get_output_data('IHP', selected_date_str)
    output_data_fhp = get_output_data('FHP', selected_date_str)
    performance_data['IHP']['Output'] = {'pronostico': output_data_ihp.get('pronostico', 0), 'producido': output_data_ihp.get('output', 0)}
    performance_data['FHP']['Output'] = {'pronostico': output_data_fhp.get('pronostico', 0), 'producido': output_data_fhp.get('output', 0)}

    # 3. Calcular KPIs a partir de los datos obtenidos para evitar nuevas llamadas a la BD
    total_pronostico = 0
    total_producido = 0
    group_kpis = {}

    for group, areas in performance_data.items():
        group_pronostico = 0
        group_producido = 0
        for area, data in areas.items():
            if area == 'Output':
                group_pronostico += data.get('pronostico', 0)
                group_producido += data.get('producido', 0)
            else:
                for turno, turno_data in data.items():
                    group_pronostico += turno_data.get('pronostico', 0)
                    group_producido += turno_data.get('producido', 0)
        
        total_pronostico += group_pronostico
        total_producido += group_producido
        
        group_eficiencia = (group_producido / group_pronostico * 100) if group_pronostico > 0 else 0
        group_kpis[group] = {
            'pronostico': f"{group_pronostico:,.0f}",
            'producido': f"{group_producido:,.0f}",
            'eficiencia': round(group_eficiencia, 2)
        }

    total_eficiencia = (total_producido / total_pronostico * 100) if total_pronostico > 0 else 0
    global_kpis = {
        'pronostico': f"{total_pronostico:,.0f}",
        'producido': f"{total_producido:,.0f}",
        'eficiencia': round(total_eficiencia, 2)
    }

    # 4. Establecer la etiqueta del período
    business_today = get_business_date()
    period_label = f"Hoy ({selected_date_str})" if selected_date == business_today else f"Día: {selected_date_str}"

    return render_template(
        'dashboard_admin.html', 
        period_label=period_label, 
        selected_date=selected_date_str, 
        global_kpis=global_kpis,
        ihp_data=group_kpis.get('IHP', {}), 
        fhp_data=group_kpis.get('FHP', {}), 
        nombres_turnos=NOMBRES_TURNOS,
        horas_turno=HORAS_TURNO,
        performance_data=performance_data,
        AREAS_IHP=AREAS_IHP,
        AREAS_FHP=AREAS_FHP
    )

@app.route('/dashboard/<group>')
@login_required
def dashboard_group(group):
    group_upper = group.upper()
    if group_upper not in ['IHP', 'FHP']: abort(404)
    if session.get('role') not in [group_upper, 'ADMIN']:
        flash('No tienes permiso para ver este dashboard.', 'danger')
        return redirect(url_for('dashboard'))
    
    business_today = get_business_date()
    today_str = business_today.strftime('%Y-%m-%d')
    yesterday_str = (business_today - timedelta(days=1)).strftime('%Y-%m-%d')
    
    summary_today = get_group_performance(group_upper, today_str)
    summary_yesterday = get_group_performance(group_upper, yesterday_str)
    
    prod_today_num = int(summary_today['producido'].replace(',', ''))
    prod_yesterday_num = int(summary_yesterday['producido'].replace(',', ''))
    
    if prod_today_num > prod_yesterday_num: summary_today['trend'] = 'up'
    elif prod_today_num < prod_yesterday_num: summary_today['trend'] = 'down'
    else: summary_today['trend'] = 'stable'
    
    performance_data = get_performance_data_from_db(group_upper, today_str)
    areas_list = [a for a in (AREAS_IHP if group_upper == 'IHP' else AREAS_FHP) if a != 'Output']
    
    for area in performance_data:
        for turno in performance_data[area]:
            turno_data = performance_data[area][turno]
            pronostico = turno_data.get('pronostico', 0)
            producido = turno_data.get('producido', 0)
            if pronostico > 0:
                turno_data['eficiencia'] = round((producido / pronostico) * 100, 1)
            else:
                turno_data['eficiencia'] = 0

    output_data = get_output_data(group_upper, today_str)
    
    return render_template('dashboard_group.html', 
                           production_data=performance_data, 
                           summary=summary_today, 
                           areas=areas_list, 
                           turnos=NOMBRES_TURNOS, 
                           today=today_str, 
                           group_name=group_upper,
                           output_data=output_data,
                           horas_turno=HORAS_TURNO)

@app.route('/registro/<group>')
@login_required
def registro(group):
    group_upper = group.upper()
    if group_upper not in ['IHP', 'FHP']:
        abort(404)
    if session.get('role') not in [group_upper, 'ADMIN']:
        flash('No tienes permiso para ver este registro.', 'danger')
        return redirect(url_for('dashboard'))
    
    selected_date_str = request.args.get('fecha', get_business_date().strftime('%Y-%m-%d'))
    try:
        selected_date = datetime.strptime(selected_date_str, '%Y-%m-%d').date()
    except ValueError:
        selected_date = get_business_date()
        selected_date_str = selected_date.strftime('%Y-%m-%d')
        flash("Formato de fecha inválido. Mostrando datos del día operativo actual.", "warning")

    areas_list = AREAS_IHP if group_upper == 'IHP' else AREAS_FHP
    
    production_data = get_performance_data_from_db(group_upper, selected_date_str)
    output_data = get_output_data(group_upper, selected_date_str)

    if group_upper == 'FHP':
        meta_produccion = 4830
    else: 
        meta_produccion = 879

    detailed_hourly_data = {}
    try:
        hourly_production_rows = db_session.query(
            ProduccionCaptura.area, 
            ProduccionCaptura.hora, 
            ProduccionCaptura.valor_producido
        ).filter(
            ProduccionCaptura.fecha == selected_date,
            ProduccionCaptura.grupo == group_upper
        ).all()

        for area, hora, valor in hourly_production_rows:
            if area not in detailed_hourly_data:
                detailed_hourly_data[area] = {}
            detailed_hourly_data[area][hora] = valor or 0
    except exc.SQLAlchemyError as e:
        flash(f"Error al obtener detalle por hora: {e}", "danger")

    totals = {'pronostico': 0, 'producido': 0, 'eficiencia': 0, 'turnos': {turno: {'pronostico': 0, 'producido': 0} for turno in NOMBRES_TURNOS}}
    
    for area in production_data:
        for turno, data in production_data[area].items():
            pronostico = data.get('pronostico', 0)
            producido = data.get('producido', 0)
            totals['pronostico'] += pronostico
            totals['producido'] += producido
            if turno in totals['turnos']:
                totals['turnos'][turno]['pronostico'] += pronostico
                totals['turnos'][turno]['producido'] += producido

    totals['pronostico'] += output_data.get('pronostico', 0)
    totals['producido'] += output_data.get('output', 0)
    
    if totals['pronostico'] > 0:
        totals['eficiencia'] = (totals['producido'] / totals['pronostico']) * 100

    return render_template('registro_group.html', 
                           selected_date=selected_date_str, 
                           production_data=production_data, 
                           areas=areas_list, 
                           nombres_turnos=NOMBRES_TURNOS, 
                           output_data=output_data, 
                           group_name=group_upper, 
                           totals=totals, 
                           meta=meta_produccion,
                           horas_turno=HORAS_TURNO,
                           detailed_hourly_data=detailed_hourly_data)

@app.route('/reportes')
@login_required
@role_required(['ADMIN', 'IHP', 'FHP'])
def reportes():
    user_role = session.get('role')
    is_admin = user_role == 'ADMIN'
    default_group = user_role if user_role in ['IHP', 'FHP'] else 'IHP'
    group = request.args.get('group', default_group)
    if not is_admin: group = user_role
    today = now_mexico()
    year = request.args.get('year', today.year, type=int)
    month = request.args.get('month', today.month, type=int)
    efficiency_data = {'labels': [], 'data': []}
    try:
        num_days = calendar.monthrange(year, month)[1]
        for day in range(1, num_days + 1):
            date_str = f"{year}-{month:02d}-{day:02d}"
            performance_day = get_group_performance(group, date_str)
            eficiencia = performance_day.get('eficiencia', 0)
            if eficiencia > 0:
                efficiency_data['labels'].append(f"{day}/{month}")
                efficiency_data['data'].append(eficiencia)
    except exc.SQLAlchemyError as e:
        flash(f"Error al calcular la tendencia de eficiencia: {e}", "danger")
    
    areas_data = {'labels': [], 'data': []}
    try:
        start_of_month = datetime(year, month, 1).date()
        end_of_month = (start_of_month.replace(day=28) + timedelta(days=4)).replace(day=1) - timedelta(days=1)
        areas_list = [area for area in (AREAS_IHP if group == 'IHP' else AREAS_FHP) if area != 'Output']
        for area in areas_list:
            produccion_area = db_session.query(func.sum(ProduccionCaptura.valor_producido)).filter(
                ProduccionCaptura.grupo == group, ProduccionCaptura.area == area,
                ProduccionCaptura.fecha.between(start_of_month, end_of_month)
            ).scalar() or 0
            if produccion_area > 0:
                areas_data['labels'].append(area)
                areas_data['data'].append(produccion_area)
        
        output_mes = db_session.query(func.sum(OutputData.output)).filter(
            OutputData.grupo == group, 
            OutputData.fecha.between(start_of_month, end_of_month)
        ).scalar() or 0
        if output_mes > 0:
            areas_data['labels'].append('Output')
            areas_data['data'].append(output_mes)

    except exc.SQLAlchemyError as e:
        flash(f"Error al calcular la comparación de áreas: {e}", "danger")
        
    return render_template('reportes.html', group=group, selected_year=year, selected_month=month, is_admin=is_admin, efficiency_data=efficiency_data, areas_data=areas_data)

@app.route('/captura/<group>', methods=['GET', 'POST'])
@login_required
@csrf_required
def captura(group):
    group_upper = group.upper()
    if group_upper not in ['IHP', 'FHP']: abort(404)
    if session.get('role') not in [group_upper, 'ADMIN']:
        flash('No tienes permiso para capturar datos.', 'danger')
        return redirect(url_for('dashboard'))
    areas_list = AREAS_IHP if group_upper == 'IHP' else AREAS_FHP
    
    if request.method == 'POST':
        selected_date_str = request.form.get('fecha')
        selected_date = datetime.strptime(selected_date_str, '%Y-%m-%d').date()
        capture_date = now_mexico().date()
        
        audit_note = ""
        if selected_date != capture_date:
            audit_note = f" (Capturado el {capture_date.strftime('%Y-%m-%d')} para la fecha {selected_date_str})."

        now_dt = now_mexico()
        changes_detected = False
        try:
            all_pronosticos = db_session.query(Pronostico).filter_by(fecha=selected_date, grupo=group_upper).all()
            all_produccion = db_session.query(ProduccionCaptura).filter_by(fecha=selected_date, grupo=group_upper).all()
            existing_output = db_session.query(OutputData).filter_by(fecha=selected_date, grupo=group_upper).first()
            pronosticos_map = {(p.area, p.turno): p for p in all_pronosticos}
            produccion_map = {(p.area, p.hora): p for p in all_produccion}
            non_output_areas = [a for a in areas_list if a != 'Output']
            
            for area in non_output_areas:
                area_slug = to_slug(area)
                for turno in NOMBRES_TURNOS:
                    new_val_str = request.form.get(f'pronostico_{area_slug}_{to_slug(turno)}')
                    if new_val_str.isdigit():
                        new_val = int(new_val_str)
                        existing = pronosticos_map.get((area, turno))
                        if existing:
                            old_val = existing.valor_pronostico or 0
                            if old_val != new_val:
                                existing.valor_pronostico = new_val
                                changes_detected = True
                                details = f"Área: {area}, Turno: {turno}. Valor: {old_val} -> {new_val}.{audit_note}"
                                log_activity("Modificación Pronóstico", details, group_upper, 'Datos', 'Info')
                        else:
                            new_entry = Pronostico(fecha=selected_date, grupo=group_upper, area=area, turno=turno, valor_pronostico=new_val)
                            db_session.add(new_entry)
                            changes_detected = True
                            details = f"Área: {area}, Turno: {turno}. Valor: {new_val}.{audit_note}"
                            log_activity("Creación Pronóstico", details, group_upper, 'Datos', 'Info')
                
                for hora in sum(HORAS_TURNO.values(), []):
                    new_val_str = request.form.get(f'produccion_{area_slug}_{hora}')
                    if new_val_str.isdigit():
                        new_val = int(new_val_str)
                        existing = produccion_map.get((area, hora))
                        if existing:
                            old_val = existing.valor_producido or 0
                            if old_val != new_val:
                                existing.valor_producido = new_val
                                existing.usuario_captura = session.get('username')
                                existing.fecha_captura = now_dt
                                changes_detected = True
                                details = f"Área: {area}, Hora: {hora}. Valor: {old_val} -> {new_val}.{audit_note}"
                                log_activity("Modificación Producción", details, group_upper, 'Datos', 'Info')
                        else:
                            new_entry = ProduccionCaptura(fecha=selected_date, grupo=group_upper, area=area, hora=hora, valor_producido=new_val, usuario_captura=session.get('username'), fecha_captura=now_dt)
                            db_session.add(new_entry)
                            changes_detected = True
                            details = f"Área: {area}, Hora: {hora}. Valor: {new_val}.{audit_note}"
                            log_activity("Creación Producción", details, group_upper, 'Datos', 'Info')
            
            new_pron_out_str = request.form.get('pronostico_output')
            new_prod_out_str = request.form.get('produccion_output')
            if existing_output:
                old_pron = existing_output.pronostico or 0
                old_prod = existing_output.output or 0
                if new_pron_out_str.isdigit() and int(new_pron_out_str) != old_pron:
                    changes_detected = True
                    details = f"Valor: {old_pron} -> {new_pron_out_str}.{audit_note}"
                    log_activity("Modificación Output Pronóstico", details, group_upper, 'Datos', 'Info')
                    existing_output.pronostico = int(new_pron_out_str)
                if new_prod_out_str.isdigit() and int(new_prod_out_str) != old_prod:
                    changes_detected = True
                    details = f"Valor: {old_prod} -> {new_prod_out_str}.{audit_note}"
                    log_activity("Modificación Output Producción", details, group_upper, 'Datos', 'Info')
                    existing_output.output = int(new_prod_out_str)
            elif new_pron_out_str.isdigit() or new_prod_out_str.isdigit():
                changes_detected = True
                new_output = OutputData(fecha=selected_date, grupo=group_upper, pronostico=int(new_pron_out_str or 0), output=int(new_prod_out_str or 0), usuario_captura=session.get('username'), fecha_captura=now_dt)
                db_session.add(new_output)
                details = f"Pronóstico: {new_pron_out_str}, Producción: {new_prod_out_str}.{audit_note}"
                log_activity("Creación Output", details, group_upper, 'Datos', 'Info')
            
            db_session.commit()
            if changes_detected: flash('Cambios guardados y registrados exitosamente.', 'success')
            else: flash('No se detectaron cambios para guardar.', 'info')
        except exc.SQLAlchemyError as e:
            db_session.rollback()
            flash(f"Error al guardar en la base de datos: {e}", 'danger')
        return redirect(url_for('captura', group=group, fecha=selected_date_str))
        
    selected_date_str = request.args.get('fecha', get_business_date().strftime('%Y-%m-%d'))
    try:
        selected_date = datetime.strptime(selected_date_str, '%Y-%m-%d').date()
    except ValueError:
        selected_date = get_business_date()
        selected_date_str = selected_date.strftime('%Y-%m-%d')
        flash("Formato de fecha inválido. Mostrando datos del día operativo actual.", "warning")

    data_for_template = get_structured_capture_data(group_upper, selected_date)
    output_data = get_output_data(group_upper, selected_date_str)
    return render_template('captura_group.html', areas=areas_list, horas_turno=HORAS_TURNO, nombres_turnos=NOMBRES_TURNOS, selected_date=selected_date_str, data=data_for_template, output_data=output_data, group_name=group_upper)

@app.route('/submit_reason', methods=['POST'])
@login_required
@csrf_required
def submit_reason():
    try:
        date_str, area, group, reason, turno_name = request.form.get('date'), request.form.get('area'), request.form.get('group'), request.form.get('reason'), request.form.get('turno_name')
        date_obj = datetime.strptime(date_str, '%Y-%m-%d').date()
        username = session.get('username')
        pronostico_entry = db_session.query(Pronostico).filter_by(fecha=date_obj, grupo=group, area=area, turno=turno_name).first()
        if pronostico_entry:
            old_reason = pronostico_entry.razon_desviacion
            pronostico_entry.razon_desviacion, pronostico_entry.usuario_razon, pronostico_entry.fecha_razon = reason, username, datetime.utcnow()
            if old_reason != reason: 
                log_activity("Registro de Razón", f"Área: {area}, Turno: {turno_name}. Razón: '{reason}'", group, 'Datos', 'Warning')
            db_session.commit()
            return jsonify({'status': 'success', 'message': 'Razón guardada exitosamente.'})
        else:
            new_entry = Pronostico(fecha=date_obj, grupo=group, area=area, turno=turno_name, valor_pronostico=0, razon_desviacion=reason, usuario_razon=username, fecha_razon=datetime.utcnow())
            db_session.add(new_entry)
            log_activity("Registro de Razón (Nuevo)", f"Área: {area}, Turno: {turno_name}. Razón: '{reason}'", group, 'Datos', 'Warning')
            db_session.commit()
            return jsonify({'status': 'success', 'message': 'Razón guardada exitosamente para un nuevo registro.'})
    except exc.SQLAlchemyError as e:
        db_session.rollback()
        return jsonify({'status': 'error', 'message': f'Error en la base de datos: {e}'}), 500
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Ocurrió un error inesperado: {e}'}), 500

@app.route('/export_excel/<group>')
@login_required
def export_excel(group):
    group_upper = group.upper()
    if group_upper not in ['IHP', 'FHP']:
        abort(404)
    if session.get('role') not in [group_upper, 'ADMIN']:
        flash('No tienes permiso para exportar estos datos.', 'danger')
        return redirect(url_for('dashboard'))
    
    selected_date = request.args.get('fecha', get_business_date().strftime('%Y-%m-%d'))
    production_data = get_performance_data_from_db(group_upper, selected_date)
    output_data = get_output_data(group_upper, selected_date)
    
    if group_upper == 'FHP':
        meta_produccion = 4830
    else:
        meta_produccion = 879
    
    records = []
    for area, turnos_data in production_data.items():
        record = {'Área': area}
        total_pronostico_area = 0
        total_producido_area = 0
        for turno, data in turnos_data.items():
            pronostico = data.get('pronostico', 0)
            producido = data.get('producido', 0)
            record[f'Pronóstico {turno}'] = pronostico
            record[f'Producido {turno}'] = producido
            total_pronostico_area += pronostico
            total_producido_area += producido
        record['Pronóstico Total'] = total_pronostico_area
        record['Producido Total'] = total_producido_area
        records.append(record)
        
    if output_data and (output_data.get('pronostico') or output_data.get('output')):
        output_record = {'Área': 'Output'}
        for turno in NOMBRES_TURNOS:
            output_record[f'Pronóstico {turno}'] = None 
            output_record[f'Producido {turno}'] = None
        output_record['Pronóstico Total'] = output_data.get('pronostico', 0)
        output_record['Producido Total'] = output_data.get('output', 0)
        records.append(output_record)

    if not records:
        flash('No hay datos para exportar en la fecha seleccionada.', 'warning')
        return redirect(url_for('registro', group=group_upper, fecha=selected_date))
        
    df = pd.DataFrame(records)
    
    cols = ['Área']
    for turno in NOMBRES_TURNOS:
        cols.append(f'Pronóstico {turno}')
        cols.append(f'Producido {turno}')
    cols.extend(['Pronóstico Total', 'Producido Total'])
    df = df[cols]
    df['Meta'] = meta_produccion

    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='RegistroProduccion', startrow=1)
        workbook, worksheet = writer.book, writer.sheets['RegistroProduccion']
        
        header_format = workbook.add_format({'bold': True, 'text_wrap': True, 'valign': 'top', 'fg_color': '#D7E4BC', 'border': 1})
        title_format = workbook.add_format({'bold': True, 'font_size': 14})
        
        worksheet.write('A1', f'Reporte de Producción - {group_upper} ({selected_date})', title_format)
        
        for col_num, value in enumerate(df.columns.values):
            worksheet.write(1, col_num, value, header_format)
        
        worksheet.set_column('A:A', 20)
        worksheet.set_column('B:Z', 15)

        column_chart = workbook.add_chart({'type': 'column'})
        num_rows = len(df)
        
        producido_total_col_letter = chr(ord('A') + df.columns.get_loc('Producido Total'))
        meta_col_letter = chr(ord('A') + df.columns.get_loc('Meta'))

        column_chart.add_series({
            'name':       f'=RegistroProduccion!${producido_total_col_letter}$2',
            'categories': f'=RegistroProduccion!$A$3:$A${num_rows + 2}',
            'values':     f'=RegistroProduccion!${producido_total_col_letter}$3:${producido_total_col_letter}${num_rows + 2}',
            'fill':       {'color': '#24b817'},
            'border':     {'color': '#1c8c11'}
        })

        line_chart = workbook.add_chart({'type': 'line'})
        line_chart.add_series({
            'name':       f'=RegistroProduccion!${meta_col_letter}$2',
            'categories': f'=RegistroProduccion!$A$3:$A${num_rows + 2}',
            'values':     f'=RegistroProduccion!${meta_col_letter}$3:${meta_col_letter}${num_rows + 2}',
            'line':       {'color': 'red', 'width': 2.25, 'dash_type': 'solid'}
        })

        column_chart.combine(line_chart)
        column_chart.set_title({'name': 'Producción por Área vs. Meta'})
        column_chart.set_x_axis({'name': 'Áreas'})
        column_chart.set_y_axis({'name': 'Unidades'})
        column_chart.set_size({'width': 720, 'height': 480})
        
        worksheet.insert_chart(f'A{num_rows + 5}', column_chart)

    output.seek(0)
    return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', as_attachment=True, download_name=f'produccion_{group_upper}_{selected_date}.xlsx')


@app.route('/centro_acciones')
@login_required
@role_required(['ADMIN'])
def centro_acciones():
    if request.args.get('limpiar'):
        session.pop('acciones_filtros', None)
        return redirect(url_for('centro_acciones'))

    filtros = session.get('acciones_filtros', {})
    if request.method == 'GET' and any(arg in request.args for arg in ['fecha_inicio', 'fecha_fin', 'grupo', 'tipo', 'status']):
        filtros = {
            'fecha_inicio': request.args.get('fecha_inicio'),
            'fecha_fin': request.args.get('fecha_fin'),
            'grupo': request.args.get('grupo'),
            'tipo': request.args.get('tipo', 'Todos'),
            'status': request.args.get('status', 'Todos')
        }
        session['acciones_filtros'] = filtros
    
    items = []

    if filtros.get('tipo', 'Todos') in ['Todos', 'Desviacion']:
        query_desviaciones = db_session.query(Pronostico).filter(Pronostico.razon_desviacion.isnot(None), Pronostico.razon_desviacion != '')
        if filtros.get('fecha_inicio'): query_desviaciones = query_desviaciones.filter(Pronostico.fecha >= datetime.strptime(filtros['fecha_inicio'], '%Y-%m-%d').date())
        if filtros.get('fecha_fin'): query_desviaciones = query_desviaciones.filter(Pronostico.fecha <= datetime.strptime(filtros['fecha_fin'], '%Y-%m-%d').date())
        if filtros.get('grupo') and filtros.get('grupo') != 'Todos': query_desviaciones = query_desviaciones.filter(Pronostico.grupo == filtros['grupo'])
        if filtros.get('status') and filtros.get('status') != 'Todos': query_desviaciones = query_desviaciones.filter(Pronostico.status == filtros['status'])
        
        for d in query_desviaciones.all():
            items.append({
                'id': d.id, 'tipo': 'Desviación', 'timestamp': d.fecha_razon, 'fecha_evento': d.fecha,
                'grupo': d.grupo, 'area': d.area, 'turno': d.turno, 'usuario': d.usuario_razon,
                'detalles': d.razon_desviacion, 'status': d.status
            })

    if filtros.get('tipo', 'Todos') in ['Todos', 'Correccion']:
        query_solicitudes = db_session.query(SolicitudCorreccion)
        if filtros.get('fecha_inicio'): query_solicitudes = query_solicitudes.filter(SolicitudCorreccion.fecha_problema >= datetime.strptime(filtros['fecha_inicio'], '%Y-%m-%d').date())
        if filtros.get('fecha_fin'): query_solicitudes = query_solicitudes.filter(SolicitudCorreccion.fecha_problema <= datetime.strptime(filtros['fecha_fin'], '%Y-%m-%d').date())
        if filtros.get('grupo') and filtros.get('grupo') != 'Todos': query_solicitudes = query_solicitudes.filter(SolicitudCorreccion.grupo == filtros['grupo'])
        if filtros.get('status') and filtros.get('status') != 'Todos': query_solicitudes = query_solicitudes.filter(SolicitudCorreccion.status == filtros['status'])

        for s in query_solicitudes.all():
            items.append({
                'id': s.id, 'tipo': f"Corrección ({s.tipo_error})", 'timestamp': s.timestamp, 'fecha_evento': s.fecha_problema,
                'grupo': s.grupo, 'area': s.area, 'turno': s.turno, 'usuario': s.usuario_solicitante,
                'detalles': s.descripcion, 'status': s.status
            })

    items.sort(key=lambda x: x['timestamp'] if x['timestamp'] else datetime.min, reverse=True)

    return render_template('centro_acciones.html', items=items, filtros=filtros)


@app.route('/solicitar_correccion', methods=['POST'])
@login_required
@csrf_required
def solicitar_correccion():
    try:
        nueva_solicitud = SolicitudCorreccion(
            usuario_solicitante=session.get('username'),
            fecha_problema=datetime.strptime(request.form.get('fecha_problema'), '%Y-%m-%d').date(),
            grupo=request.form.get('grupo'),
            area=request.form.get('area'),
            turno=request.form.get('turno'),
            tipo_error=request.form.get('tipo_error'),
            descripcion=request.form.get('descripcion')
        )
        db_session.add(nueva_solicitud)
        log_activity(f"Solicitud Corrección ({request.form.get('tipo_error')})", 
                     f"Área: {request.form.get('area')}, Turno: {request.form.get('turno')}. Fecha: {request.form.get('fecha_problema')}", 
                     request.form.get('grupo'), 'Datos', 'Warning')
        db_session.commit()
        return jsonify({'status': 'success', 'message': 'Tu solicitud de corrección ha sido enviada. Un administrador la revisará pronto.'})
    except Exception as e:
        db_session.rollback()
        print(f"Error al crear solicitud de corrección: {e}")
        return jsonify({'status': 'error', 'message': f'Ocurrió un error al enviar tu solicitud: {e}'}), 500

@app.route('/update_reason_status/<int:reason_id>', methods=['POST'])
@login_required
@role_required(['ADMIN'])
@csrf_required
def update_reason_status(reason_id):
    new_status = request.form.get('status')
    reason = db_session.query(Pronostico).get(reason_id)
    if reason and new_status:
        old_status = reason.status
        reason.status = new_status
        log_activity("Cambio Estado (Desviación)", f"ID Razón: {reason.id}. Estado: '{old_status}' -> '{new_status}'.", reason.grupo, 'Datos', 'Info')
        db_session.commit()
        flash(f"El estado de la razón ha sido actualizado a '{new_status}'.", 'success')
    else:
        flash("No se pudo actualizar el estado de la razón.", 'danger')
    return redirect(url_for('centro_acciones'))


@app.route('/update_solicitud_status/<int:solicitud_id>', methods=['POST'])
@login_required
@role_required(['ADMIN'])
@csrf_required
def update_solicitud_status(solicitud_id):
    solicitud = db_session.query(SolicitudCorreccion).get(solicitud_id)
    if solicitud:
        solicitud.status = request.form.get('status')
        solicitud.admin_username = session.get('username')
        solicitud.admin_notas = request.form.get('admin_notas')
        solicitud.fecha_resolucion = datetime.utcnow()
        log_activity("Cambio Estado (Corrección)", f"ID Solicitud: {solicitud.id}. Estado: '{solicitud.status}' -> '{request.form.get('status')}'.", solicitud.grupo, 'Datos', 'Info')
        db_session.commit()
        flash('El estado de la solicitud ha sido actualizado.', 'success')
    else:
        flash('No se encontró la solicitud especificada.', 'danger')
    return redirect(url_for('centro_acciones'))

@app.route('/manage_users', methods=['GET', 'POST'])
@login_required
@role_required(['ADMIN'])
@csrf_required
def manage_users():
    if request.method == 'POST':
        form_type = request.form.get('form_type')
        if form_type == 'create_user':
            username = request.form.get('username')
            password = request.form.get('password')
            role = request.form.get('role')
            nombre_completo = request.form.get('nombre_completo')
            cargo = request.form.get('cargo')
            turno = request.form.get('turno') 
            if not all([username, password, role, nombre_completo, cargo]):
                flash('Todos los campos son obligatorios.', 'warning')
            else:
                if db_session.query(Usuario).filter_by(username=username).first():
                    flash(f"El nombre de usuario '{username}' ya existe.", 'danger')
                else:
                    new_user = Usuario(username=username, password=password, role=role, nombre_completo=nombre_completo, cargo=cargo, turno=turno)
                    db_session.add(new_user)
                    log_activity("Creación de usuario", f"Usuario '{username}' ({nombre_completo}) creado con rol '{role}'.", 'ADMIN', 'Seguridad', 'Info')
                    db_session.commit()
                    flash(f"Usuario '{username}' creado exitosamente.", 'success')
            return redirect(url_for('manage_users'))
    if request.args.get('limpiar'):
        session.pop('user_filtros', None)
        return redirect(url_for('manage_users'))
    filtros = {}
    if request.method == 'GET' and any(arg in request.args for arg in ['username', 'nombre_completo', 'role', 'turno']):
        filtros = {
            'username': request.args.get('username', ''),
            'nombre_completo': request.args.get('nombre_completo', ''),
            'role': request.args.get('role', ''),
            'turno': request.args.get('turno', '')
        }
        session['user_filtros'] = filtros
    elif 'user_filtros' in session:
        filtros = session.get('user_filtros', {})
    query = db_session.query(Usuario)
    if filtros.get('username'):
        query = query.filter(Usuario.username.ilike(f"%{filtros['username']}%"))
    if filtros.get('nombre_completo'):
        query = query.filter(Usuario.nombre_completo.ilike(f"%{filtros['nombre_completo']}%"))
    if filtros.get('role') and filtros.get('role') != 'Todos':
        query = query.filter(Usuario.role == filtros['role'])
    if filtros.get('turno') and filtros.get('turno') != 'Todos':
        if filtros.get('turno') == 'N/A':
             query = query.filter((Usuario.turno == None) | (Usuario.turno == ''))
        else:
            query = query.filter(Usuario.turno == filtros['turno'])
    users = query.order_by(Usuario.id).all()
    return render_template('manage_users.html', users=users, nombres_turnos=NOMBRES_TURNOS, filtros=filtros)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required(['ADMIN'])
@csrf_required
def edit_user(user_id):
    user = db_session.query(Usuario).get(user_id)
    if not user:
        abort(404)
    if request.method == 'POST':
        new_username = request.form.get('username')
        if new_username != user.username and db_session.query(Usuario).filter_by(username=new_username).first():
            flash(f"El nombre de usuario '{new_username}' ya existe.", 'danger')
            return render_template('edit_user.html', user=user, nombres_turnos=NOMBRES_TURNOS)
        user.username = new_username
        user.nombre_completo = request.form.get('nombre_completo')
        user.cargo = request.form.get('cargo')
        user.role = request.form.get('role')
        user.turno = request.form.get('turno')
        password = request.form.get('password')
        if password:
            user.password_hash = generate_password_hash(password)
        try:
            log_activity("Edición de usuario", f"Datos del usuario ID {user.id} ({user.username}) actualizados.", 'ADMIN', 'Seguridad', 'Warning')
            db_session.commit()
            flash('Usuario actualizado correctamente.', 'success')
            return redirect(url_for('manage_users'))
        except exc.IntegrityError:
            db_session.rollback()
            flash(f"Error: El nombre de usuario '{new_username}' ya está en uso.", 'danger')
    return render_template('edit_user.html', user=user, nombres_turnos=NOMBRES_TURNOS)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@role_required(['ADMIN'])
@csrf_required
def delete_user(user_id):
    if user_id == session.get('user_id'):
        flash('No puedes eliminar tu propia cuenta de administrador.', 'danger')
        return redirect(url_for('manage_users'))
    user_to_delete = db_session.query(Usuario).filter_by(id=user_id).first()
    if user_to_delete:
        username_to_delete = user_to_delete.username
        log_activity("Eliminación de usuario", f"Usuario '{username_to_delete}' (ID: {user_id}) fue eliminado.", 'ADMIN', 'Seguridad', 'Critical')
        db_session.delete(user_to_delete)
        db_session.commit()
        flash('Usuario eliminado exitosamente.', 'success')
    else:
        flash('El usuario no existe.', 'danger')
    return redirect(url_for('manage_users'))

@app.route('/activity_log')
@login_required
@role_required(['ADMIN'])
def activity_log():
    if request.args.get('limpiar'):
        session.pop('log_filtros', None)
        return redirect(url_for('activity_log'))
    
    filtros = session.get('log_filtros', {}) if not request.args else {
        'fecha_inicio': request.args.get('fecha_inicio'), 
        'fecha_fin': request.args.get('fecha_fin'), 
        'usuario': request.args.get('usuario'), 
        'area_grupo': request.args.get('area_grupo'),
        'category': request.args.get('category'),
        'severity': request.args.get('severity')
    }
    session['log_filtros'] = filtros
    
    query = db_session.query(ActivityLog, Usuario).outerjoin(Usuario, ActivityLog.username == Usuario.username)
    
    if filtros.get('fecha_inicio'): query = query.filter(ActivityLog.timestamp >= datetime.strptime(filtros['fecha_inicio'], '%Y-%m-%d'))
    if filtros.get('fecha_fin'): 
        end_date = datetime.strptime(filtros['fecha_fin'], '%Y-%m-%d') + timedelta(days=1)
        query = query.filter(ActivityLog.timestamp < end_date)
    if filtros.get('usuario'): query = query.filter(ActivityLog.username.ilike(f"%{filtros['usuario']}%"))
    if filtros.get('area_grupo') and filtros.get('area_grupo') != 'Todos': query = query.filter(ActivityLog.area_grupo == filtros['area_grupo'])
    if filtros.get('category') and filtros.get('category') != 'Todos': query = query.filter(ActivityLog.category == filtros['category'])
    if filtros.get('severity') and filtros.get('severity') != 'Todos': query = query.filter(ActivityLog.severity == filtros['severity'])
    
    logs = query.order_by(ActivityLog.timestamp.desc()).limit(500).all()
    
    log_categories = ['Autenticación', 'Datos', 'Seguridad', 'Sistema', 'General']
    log_severities = ['Info', 'Warning', 'Critical']

    return render_template('activity_log.html', logs=logs, filtros=filtros, log_categories=log_categories, log_severities=log_severities)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=False if os.getenv('RENDER') else True)
