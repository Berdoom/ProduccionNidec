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

# --- Importaciones de la Base de Datos ---
from sqlalchemy import func, exc, extract
from database import db_session, Usuario, Pronostico, ProduccionCaptura, ActivityLog, OutputData

# --- Configurar locale para español (para nombres de meses y días) ---
try:
    locale.setlocale(locale.LC_TIME, 'es_ES.UTF-8')
except locale.Error:
    try:
        locale.setlocale(locale.LC_TIME, 'Spanish_Spain')
    except locale.Error:
        print("Locale 'es_ES' no encontrado, usando el default.")

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "una-clave-secreta-de-respaldo-muy-segura")

# Configuración del tiempo de expiración de la sesión por inactividad
app.permanent_session_lifetime = timedelta(minutes=30)

# --- Filtro personalizado para obtener el nombre del mes en español ---
def month_name_filter(month_number):
    try:
        return calendar.month_name[int(month_number)].capitalize()
    except (IndexError, ValueError):
        return ''

app.jinja_env.filters['month_name'] = month_name_filter

@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()

@app.before_request
def before_request_handler():
    """Se ejecuta antes de cada petición para reiniciar el temporizador de sesión."""
    session.permanent = True

# --- Constantes y Funciones de Utilidad ---
AREAS_IHP = ['Soporte', 'Cuerpos', 'Misceláneos', 'Embobinado', 'ECC', 'ERF', 'Carga', 'Output']
AREAS_FHP = ['Rotores Inyección', 'Rotores ERF', 'Cuerpos', 'Flechas', 'Embobinado', 'Barniz', 'Soporte', 'Pintura', 'Output']
HORAS_TURNO = { 'Turno A': ['10AM', '1PM', '4PM'], 'Turno B': ['7PM', '10PM', '12AM'], 'Turno C': ['3AM', '6AM'] }
NOMBRES_TURNOS = list(HORAS_TURNO.keys())

def to_slug(text):
    """Convierte un texto a un formato 'slug' seguro para IDs y nombres de campo."""
    return text.replace(' ', '_').replace('.', '').replace('/', '')

app.jinja_env.filters['slug'] = to_slug

def log_activity(action, details="", area_grupo=None):
    """Registra una actividad en la base de datos."""
    try:
        log_entry = ActivityLog(
            timestamp=datetime.now(),
            username=session.get('username', 'Sistema'),
            action=action,
            details=details,
            area_grupo=area_grupo
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
            session['csrf_token'] = secrets.token_hex(16)
            log_activity("Inicio de sesión", f"Usuario '{user.username}' (Rol: {user.role})", area_grupo='Sistema')
            db_session.commit()
            return redirect(url_for('dashboard'))
        else:
            flash('Usuario o contraseña incorrectos.', 'danger')
    if 'csrf_token' not in session: session['csrf_token'] = secrets.token_hex(16)
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    username = session.get('username', 'Desconocido')
    log_activity("Cierre de sesión", f"Usuario '{username}'", area_grupo='Sistema')
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
        query_pronostico = db_session.query(func.sum(Pronostico.valor_pronostico)).filter(Pronostico.grupo == group_name, Pronostico.fecha.between(start_date, end_date))
        total_pronostico = query_pronostico.scalar() or 0
        query_producido = db_session.query(func.sum(ProduccionCaptura.valor_producido)).filter(ProduccionCaptura.grupo == group_name, ProduccionCaptura.fecha.between(start_date, end_date))
        total_producido = query_producido.scalar() or 0
        eficiencia = (total_producido / total_pronostico * 100) if total_pronostico > 0 else 0
        return {'pronostico': f"{total_pronostico:,.0f}", 'producido': f"{total_producido:,.0f}", 'eficiencia': round(eficiencia, 2)}
    except exc.SQLAlchemyError as e:
        flash(f"Error al calcular el rendimiento del grupo: {e}", "danger")
        return {'pronostico': 0, 'producido': 0, 'eficiencia': 0}

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
        if output_row: return {'pronostico': output_row.pronostico or '', 'output': output_row.output or ''}
    except exc.SQLAlchemyError as e:
        flash(f"Error al obtener datos de Output: {e}", "danger")
    return {'pronostico': '', 'output': ''}

# --- NUEVAS FUNCIONES PARA EL DASHBOARD ANALITICO ---
def get_heatmap_data(selected_date):
    heatmap = {'IHP': {}, 'FHP': {}}
    all_areas = {'IHP': AREAS_IHP, 'FHP': AREAS_FHP}
    try:
        for group, areas in all_areas.items():
            for area in [a for a in areas if a != 'Output']:
                heatmap[group][area] = {}
                for turno in NOMBRES_TURNOS:
                    pronostico_val = db_session.query(func.sum(Pronostico.valor_pronostico)).filter(
                        Pronostico.fecha == selected_date, Pronostico.grupo == group,
                        Pronostico.area == area, Pronostico.turno == turno
                    ).scalar() or 0
                    horas_turno = HORAS_TURNO.get(turno, [])
                    producido_val = db_session.query(func.sum(ProduccionCaptura.valor_producido)).filter(
                        ProduccionCaptura.fecha == selected_date, ProduccionCaptura.grupo == group,
                        ProduccionCaptura.area == area, ProduccionCaptura.hora.in_(horas_turno)
                    ).scalar() or 0
                    eficiencia = 0
                    if pronostico_val > 0:
                        eficiencia = round((producido_val / pronostico_val) * 100, 1)
                    heatmap[group][area][turno] = eficiencia
    except exc.SQLAlchemyError as e:
        flash(f"Error al generar datos del mapa de calor: {e}", "danger")
    return heatmap

def get_latest_deviations(limit=5):
    try:
        deviations = db_session.query(Pronostico).filter(
            Pronostico.razon_desviacion.isnot(None),
            Pronostico.razon_desviacion != '',
            Pronostico.status != 'Resuelto'
        ).order_by(Pronostico.fecha.desc(), Pronostico.id.desc()).limit(limit).all()
        return deviations
    except exc.SQLAlchemyError as e:
        flash(f"Error al obtener últimas desviaciones: {e}", "danger")
        return []

def get_heatmap_color_class(eficiencia):
    if eficiencia == 0: return 'heatmap-zero'
    if eficiencia < 80: return 'heatmap-danger'
    if eficiencia < 95: return 'heatmap-warning'
    if eficiencia <= 105: return 'heatmap-success'
    return 'heatmap-excellent'

app.jinja_env.filters['heatmap_color'] = get_heatmap_color_class

# --- Rutas de Dashboards y Registros ---
@app.route('/dashboard/admin')
@login_required
@role_required(['ADMIN'])
def dashboard_admin():
    # Obtener la fecha de los argumentos de la URL, si no existe, usar la fecha de hoy
    selected_date_str = request.args.get('fecha', datetime.now().strftime('%Y-%m-%d'))
    try:
        selected_date = datetime.strptime(selected_date_str, '%Y-%m-%d').date()
    except ValueError:
        # Si el formato de fecha es inválido, usar la fecha de hoy y notificar al usuario
        selected_date = datetime.now().date()
        selected_date_str = selected_date.strftime('%Y-%m-%d')
        flash("Formato de fecha inválido. Mostrando datos de hoy.", "warning")

    # 1. KPIs para la fecha seleccionada
    ihp_data = get_group_performance('IHP', selected_date_str)
    fhp_data = get_group_performance('FHP', selected_date_str)
    
    total_pronostico = (int(ihp_data['pronostico'].replace(',', '')) + int(fhp_data['pronostico'].replace(',', '')))
    total_producido = (int(ihp_data['producido'].replace(',', '')) + int(fhp_data['producido'].replace(',', '')))
    total_eficiencia = (total_producido / total_pronostico * 100) if total_pronostico > 0 else 0
    
    global_kpis = {
        'pronostico': f"{total_pronostico:,.0f}",
        'producido': f"{total_producido:,.0f}",
        'eficiencia': round(total_eficiencia, 2)
    }

    # 2. Datos para el mapa de calor de la fecha seleccionada
    heatmap_data = get_heatmap_data(selected_date)
    
    # 3. Últimas desviaciones (esto es independiente de la fecha seleccionada)
    latest_deviations = get_latest_deviations()

    # Etiqueta para mostrar en la UI
    today = datetime.now().date()
    if selected_date == today:
        period_label = f"Hoy ({selected_date_str})"
    else:
        period_label = f"Día: {selected_date_str}"

    return render_template(
        'dashboard_admin.html', 
        period_label=period_label,
        selected_date=selected_date_str,
        global_kpis=global_kpis,
        ihp_data=ihp_data, 
        fhp_data=fhp_data,
        heatmap_data=heatmap_data,
        latest_deviations=latest_deviations,
        nombres_turnos=NOMBRES_TURNOS
    )

@app.route('/dashboard/<group>')
@login_required
def dashboard_group(group):
    group_upper = group.upper()
    if group_upper not in ['IHP', 'FHP']: abort(404)
    if session.get('role') not in [group_upper, 'ADMIN']:
        flash('No tienes permiso para ver este dashboard.', 'danger')
        return redirect(url_for('dashboard'))
    today_str = datetime.now().strftime('%Y-%m-%d')
    yesterday_str = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
    summary_today = get_group_performance(group_upper, today_str)
    summary_yesterday = get_group_performance(group_upper, yesterday_str)
    prod_today_num = int(summary_today['producido'].replace(',', ''))
    prod_yesterday_num = int(summary_yesterday['producido'].replace(',', ''))
    if prod_today_num > prod_yesterday_num: summary_today['trend'] = 'up'
    elif prod_today_num < prod_yesterday_num: summary_today['trend'] = 'down'
    else: summary_today['trend'] = 'stable'
    performance_data = get_performance_data_from_db(group_upper, today_str)
    areas_list = [a for a in (AREAS_IHP if group_upper == 'IHP' else AREAS_FHP) if a != 'Output']
    return render_template('dashboard_group.html', production_data=performance_data, summary=summary_today, areas=areas_list, turnos=NOMBRES_TURNOS, today=today_str, group_name=group_upper)

@app.route('/registro/<group>')
@login_required
def registro(group):
    group_upper = group.upper()
    if group_upper not in ['IHP', 'FHP']: abort(404)
    if session.get('role') not in [group_upper, 'ADMIN']:
        flash('No tienes permiso para ver este registro.', 'danger')
        return redirect(url_for('dashboard'))
    selected_date = request.args.get('fecha', datetime.now().strftime('%Y-%m-%d'))
    areas_list = AREAS_IHP if group_upper == 'IHP' else AREAS_FHP
    production_data = get_performance_data_from_db(group_upper, selected_date)
    output_data = get_output_data(group_upper, selected_date)
    meta_produccion = 879
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
    if totals['pronostico'] > 0:
        totals['eficiencia'] = (totals['producido'] / totals['pronostico']) * 100
    return render_template('registro_group.html', selected_date=selected_date, production_data=production_data, areas=areas_list, nombres_turnos=NOMBRES_TURNOS, output_data=output_data, group_name=group_upper, totals=totals, meta=meta_produccion)

@app.route('/reportes')
@login_required
@role_required(['ADMIN', 'IHP', 'FHP'])
def reportes():
    user_role = session.get('role')
    is_admin = user_role == 'ADMIN'
    default_group = user_role if user_role in ['IHP', 'FHP'] else 'IHP'
    group = request.args.get('group', default_group)
    if not is_admin: group = user_role
    today = datetime.now()
    year = request.args.get('year', today.year, type=int)
    month = request.args.get('month', today.month, type=int)
    efficiency_data = {'labels': [], 'data': []}
    try:
        num_days = calendar.monthrange(year, month)[1]
        for day in range(1, num_days + 1):
            date = datetime(year, month, day).date()
            pronostico_dia = db_session.query(func.sum(Pronostico.valor_pronostico)).filter_by(fecha=date, grupo=group).scalar() or 0
            produccion_dia = db_session.query(func.sum(ProduccionCaptura.valor_producido)).filter_by(fecha=date, grupo=group).scalar() or 0
            if pronostico_dia > 0:
                eficiencia = round((produccion_dia / pronostico_dia) * 100, 2)
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
    except exc.SQLAlchemyError as e:
        flash(f"Error al calcular la comparación de áreas: {e}", "danger")
    return render_template('reportes.html', group=group, selected_year=year, selected_month=month, is_admin=is_admin, efficiency_data=efficiency_data, areas_data=areas_data)

# --- Rutas de Interacción y Administración ---
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
        now_dt = datetime.now()
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
                                log_activity("Modificación Pronóstico", f"Fecha:{selected_date_str}, Área:{area}, Turno:{turno}. Valor cambiado de {old_val} a {new_val}", group_upper)
                        else:
                            new_entry = Pronostico(fecha=selected_date, grupo=group_upper, area=area, turno=turno, valor_pronostico=new_val)
                            db_session.add(new_entry)
                            changes_detected = True
                            log_activity("Creación Pronóstico", f"Fecha:{selected_date_str}, Área:{area}, Turno:{turno}. Valor establecido: {new_val}", group_upper)
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
                                log_activity("Modificación Producción", f"Fecha:{selected_date_str}, Área:{area}, Hora:{hora}. Valor cambiado de {old_val} a {new_val}", group_upper)
                        else:
                            new_entry = ProduccionCaptura(fecha=selected_date, grupo=group_upper, area=area, hora=hora, valor_producido=new_val, usuario_captura=session.get('username'), fecha_captura=now_dt)
                            db_session.add(new_entry)
                            changes_detected = True
                            log_activity("Creación Producción", f"Fecha:{selected_date_str}, Área:{area}, Hora:{hora}. Valor establecido: {new_val}", group_upper)
            new_pron_out_str = request.form.get('pronostico_output')
            new_prod_out_str = request.form.get('produccion_output')
            if existing_output:
                old_pron = existing_output.pronostico or 0
                old_prod = existing_output.output or 0
                if new_pron_out_str.isdigit() and int(new_pron_out_str) != old_pron:
                    changes_detected = True
                    log_activity("Modificación Output Pronóstico", f"Fecha:{selected_date_str}. Valor cambiado de {old_pron} a {new_pron_out_str}", group_upper)
                    existing_output.pronostico = int(new_pron_out_str)
                if new_prod_out_str.isdigit() and int(new_prod_out_str) != old_prod:
                    changes_detected = True
                    log_activity("Modificación Output Producción", f"Fecha:{selected_date_str}. Valor cambiado de {old_prod} a {new_prod_out_str}", group_upper)
                    existing_output.output = int(new_prod_out_str)
            elif new_pron_out_str.isdigit() or new_prod_out_str.isdigit():
                changes_detected = True
                new_output = OutputData(fecha=selected_date, grupo=group_upper, pronostico=int(new_pron_out_str or 0), output=int(new_prod_out_str or 0), usuario_captura=session.get('username'), fecha_captura=now_dt)
                db_session.add(new_output)
                log_activity("Creación Output", f"Fecha:{selected_date_str}. Pronóstico: {new_pron_out_str}, Producción: {new_prod_out_str}", group_upper)
            db_session.commit()
            if changes_detected: flash('Cambios guardados y registrados exitosamente.', 'success')
            else: flash('No se detectaron cambios para guardar.', 'info')
        except exc.SQLAlchemyError as e:
            db_session.rollback()
            flash(f"Error al guardar en la base de datos: {e}", 'danger')
        return redirect(url_for('captura', group=group, fecha=selected_date_str))
    selected_date_str = request.args.get('fecha', datetime.now().strftime('%Y-%m-%d'))
    selected_date = datetime.strptime(selected_date_str, '%Y-%m-%d').date()
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
            pronostico_entry.razon_desviacion, pronostico_entry.usuario_razon, pronostico_entry.fecha_razon = reason, username, datetime.now()
            if old_reason != reason: log_activity("Registro de Razón", f"Fecha:{date_str}, Área:{area}, Turno:{turno_name}", area_grupo=group)
            db_session.commit()
            return jsonify({'status': 'success', 'message': 'Razón guardada exitosamente.'})
        else:
            new_entry = Pronostico(fecha=date_obj, grupo=group, area=area, turno=turno_name, valor_pronostico=0, razon_desviacion=reason, usuario_razon=username, fecha_razon=datetime.now())
            db_session.add(new_entry)
            log_activity("Registro de Razón (Nuevo)", f"Fecha:{date_str}, Área:{area}, Turno:{turno_name}", area_grupo=group)
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
    if group_upper not in ['IHP', 'FHP']: abort(404)
    if session.get('role') not in [group_upper, 'ADMIN']:
        flash('No tienes permiso para exportar estos datos.', 'danger')
        return redirect(url_for('dashboard'))
    selected_date = request.args.get('fecha', datetime.now().strftime('%Y-%m-%d'))
    production_data = get_performance_data_from_db(group_upper, selected_date)
    output_data = get_output_data(group_upper, selected_date)
    meta_produccion = 879
    records = []
    for area, turnos_data in production_data.items():
        record = {'Área': area}
        total_producido_area = 0
        for turno, data in turnos_data.items():
            producido = data.get('producido', 0)
            record[f'Producido {turno}'] = producido
            total_producido_area += producido
        record['Producido Total'] = total_producido_area
        records.append(record)
    if not records:
        flash('No hay datos para exportar en la fecha seleccionada.', 'warning')
        return redirect(url_for('registro', group=group_upper, fecha=selected_date))
    df = pd.DataFrame(records)
    if output_data and output_data.get('output'):
        output_row = pd.DataFrame([{'Área': 'Output', 'Producido Total': output_data.get('output', 0)}])
        df = pd.concat([df, output_row], ignore_index=True)
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
        worksheet.set_column('A:A', 20); worksheet.set_column('B:Z', 15)
        column_chart = workbook.add_chart({'type': 'column'})
        num_rows = len(df)
        producido_total_col_letter = chr(ord('A') + df.columns.get_loc('Producido Total'))
        meta_col_letter = chr(ord('A') + df.columns.get_loc('Meta'))
        column_chart.add_series({'name': f'=RegistroProduccion!${producido_total_col_letter}$2', 'categories': f'=RegistroProduccion!$A$3:$A${num_rows + 2}', 'values': f'=RegistroProduccion!${producido_total_col_letter}$3:${producido_total_col_letter}${num_rows + 2}', 'fill': {'color': '#24b817'}, 'border': {'color': '#1c8c11'}})
        line_chart = workbook.add_chart({'type': 'line'})
        line_chart.add_series({'name': f'=RegistroProduccion!${meta_col_letter}$2', 'categories': f'=RegistroProduccion!$A$3:$A${num_rows + 2}', 'values': f'=RegistroProduccion!${meta_col_letter}$3:${meta_col_letter}${num_rows + 2}', 'line': {'color': 'red', 'width': 2.25, 'dash_type': 'solid'}})
        column_chart.combine(line_chart)
        column_chart.set_title({'name': 'Producción por Área vs. Meta'}); column_chart.set_x_axis({'name': 'Áreas'}); column_chart.set_y_axis({'name': 'Unidades'}); column_chart.set_size({'width': 720, 'height': 480})
        worksheet.insert_chart(f'A{num_rows + 5}', column_chart)
    output.seek(0)
    return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', as_attachment=True, download_name=f'produccion_{group_upper}_{selected_date}.xlsx')

@app.route('/bandeja')
@login_required
@role_required(['ADMIN'])
def bandeja():
    if request.args.get('limpiar'):
        session.pop('bandeja_filtros', None)
        return redirect(url_for('bandeja'))
    filtros = session.get('bandeja_filtros', {}) if not request.args else {'fecha_inicio': request.args.get('fecha_inicio'), 'fecha_fin': request.args.get('fecha_fin'), 'grupo': request.args.get('grupo'), 'area': request.args.get('area'), 'usuario': request.args.get('usuario'), 'status': request.args.get('status')}
    session['bandeja_filtros'] = filtros
    query = db_session.query(Pronostico).filter(Pronostico.razon_desviacion.isnot(None), Pronostico.razon_desviacion != '')
    if filtros.get('fecha_inicio'): query = query.filter(Pronostico.fecha >= datetime.strptime(filtros['fecha_inicio'], '%Y-%m-%d').date())
    if filtros.get('fecha_fin'): query = query.filter(Pronostico.fecha <= datetime.strptime(filtros['fecha_fin'], '%Y-%m-%d').date())
    if filtros.get('grupo') and filtros.get('grupo') != 'Todos': query = query.filter(Pronostico.grupo == filtros['grupo'])
    if filtros.get('area'): query = query.filter(Pronostico.area.ilike(f"%{filtros['area']}%"))
    if filtros.get('usuario'): query = query.filter(Pronostico.usuario_razon.ilike(f"%{filtros['usuario']}%"))
    if filtros.get('status') and filtros.get('status') != 'Todos': query = query.filter(Pronostico.status == filtros['status'])
    razones = query.order_by(Pronostico.fecha.desc(), Pronostico.grupo).all()
    for razon in razones:
        horas_del_turno = HORAS_TURNO.get(razon.turno, [])
        producido_turno = db_session.query(func.sum(ProduccionCaptura.valor_producido)).filter(ProduccionCaptura.fecha == razon.fecha, ProduccionCaptura.grupo == razon.grupo, ProduccionCaptura.area == razon.area, ProduccionCaptura.hora.in_(horas_del_turno)).scalar() or 0
        razon.producido_turno = producido_turno
    return render_template('bandeja.html', razones=razones, filtros=filtros)

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
        log_activity("Cambio de Estado de Razón", f"ID Razón: {reason.id}. Estado cambiado de '{old_status}' a '{new_status}'.")
        db_session.commit()
        flash(f"El estado de la razón ha sido actualizado a '{new_status}'.", 'success')
    else:
        flash("No se pudo actualizar el estado de la razón.", 'danger')
    return redirect(url_for('bandeja'))

@app.route('/manage_users', methods=['GET', 'POST'])
@login_required
@role_required(['ADMIN'])
@csrf_required
def manage_users():
    if request.method == 'POST':
        username, password, role = request.form.get('username'), request.form.get('password'), request.form.get('role')
        if not username or not password or not role: flash('Todos los campos son obligatorios.', 'warning')
        else:
            if db_session.query(Usuario).filter_by(username=username).first():
                flash(f"El nombre de usuario '{username}' ya existe.", 'danger')
            else:
                new_user = Usuario(username=username, password=password, role=role)
                db_session.add(new_user)
                log_activity("Creación de usuario", f"Admin '{session.get('username')}' creó el usuario '{username}' con el rol '{role}'.", area_grupo='ADMIN')
                db_session.commit()
                flash(f"Usuario '{username}' creado exitosamente.", 'success')
        return redirect(url_for('manage_users'))
    users = db_session.query(Usuario).all()
    return render_template('manage_users.html', users=users)

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
        db_session.delete(user_to_delete)
        log_activity("Eliminación de usuario", f"Admin '{session.get('username')}' eliminó al usuario '{username_to_delete}'.", area_grupo='ADMIN')
        db_session.commit()
        flash('Usuario eliminado exitosamente.', 'success')
    else: flash('El usuario no existe.', 'danger')
    return redirect(url_for('manage_users'))

@app.route('/activity_log')
@login_required
@role_required(['ADMIN'])
def activity_log():
    if request.args.get('limpiar'):
        session.pop('log_filtros', None)
        return redirect(url_for('activity_log'))
    filtros = session.get('log_filtros', {}) if not request.args else {'fecha_inicio': request.args.get('fecha_inicio'), 'fecha_fin': request.args.get('fecha_fin'), 'usuario': request.args.get('usuario'), 'area_grupo': request.args.get('area_grupo')}
    session['log_filtros'] = filtros
    query = db_session.query(ActivityLog)
    if filtros.get('fecha_inicio'): query = query.filter(ActivityLog.timestamp >= datetime.strptime(filtros['fecha_inicio'], '%Y-%m-%d'))
    if filtros.get('fecha_fin'): 
        end_date = datetime.strptime(filtros['fecha_fin'], '%Y-%m-%d') + timedelta(days=1)
        query = query.filter(ActivityLog.timestamp < end_date)
    if filtros.get('usuario'): query = query.filter(ActivityLog.username.ilike(f"%{filtros['usuario']}%"))
    if filtros.get('area_grupo') and filtros.get('area_grupo') != 'Todos': query = query.filter(ActivityLog.area_grupo == filtros['area_grupo'])
    logs = query.order_by(ActivityLog.timestamp.desc()).limit(500).all()
    return render_template('activity_log.html', logs=logs, filtros=filtros)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=True)