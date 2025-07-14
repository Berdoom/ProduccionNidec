import os
import sys
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
from sqlalchemy.orm import joinedload

try:
    from zoneinfo import ZoneInfo
except ImportError:
    from pytz import timezone as ZoneInfo

from sqlalchemy import func, exc, extract, or_
from database import (
    db_session, Usuario, Pronostico, ProduccionCaptura, ActivityLog, 
    OutputData, SolicitudCorreccion, init_db, create_default_admin, 
    Rol, Turno, OrdenLM, ColumnaLM, DatoCeldaLM
)

try:
    locale.setlocale(locale.LC_TIME, 'es_ES.UTF-8')
except locale.Error:
    try:
        locale.setlocale(locale.LC_TIME, 'Spanish_Spain')
    except locale.Error:
        print("Locale 'es_ES' no encontrado, usando el default.")

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "n1D3c$#pro")

# ===============================================================
# === CONFIGURACIÓN INICIAL Y CONTEXT PROCESSORS ===
# ===============================================================

@app.context_processor
def inject_global_vars():
    user = None
    if 'username' in session:
        user = db_session.query(Usuario).filter_by(username=session['username']).first()
    
    pending_actions_count = 0
    if session.get('role') == 'ADMIN':
        try:
            desviaciones_count = db_session.query(func.count(Pronostico.id)).filter(
                Pronostico.status == 'Nuevo', Pronostico.razon_desviacion.isnot(None), Pronostico.razon_desviacion != ''
            ).scalar() or 0
            correcciones_count = db_session.query(func.count(SolicitudCorreccion.id)).filter(SolicitudCorreccion.status == 'Pendiente').scalar() or 0
            pending_actions_count = desviaciones_count + correcciones_count
        except Exception as e:
            print(f"Error al contar acciones pendientes: {e}")

    return dict(current_user=user, pending_actions_count=pending_actions_count)

with app.app_context():
    init_db()
    create_default_admin()

app.permanent_session_lifetime = timedelta(minutes=30)

@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()

@app.before_request
def before_request_handler():
    session.permanent = True

# ===============================================================
# === CONSTANTES Y FUNCIONES DE UTILIDAD ===
# ===============================================================

AREAS_IHP = ['Soporte', 'Servicio', 'Cuerpos', 'Flechas', 'Misceláneos', 'Embobinado', 'ECC', 'ERF', 'Carga', 'Output']
AREAS_FHP = ['Rotores Inyección', 'Rotores ERF', 'Cuerpos', 'Flechas', 'Embobinado', 'Barniz', 'Soporte', 'Pintura', 'Carga', 'Output']
HORAS_TURNO = { 'Turno A': ['10AM', '1PM', '4PM'], 'Turno B': ['7PM', '10PM', '12AM'], 'Turno C': ['3AM', '6AM'] }
NOMBRES_TURNOS_PRODUCCION = list(HORAS_TURNO.keys())

def to_slug(text):
    return text.replace(' ', '_').replace('.', '').replace('/', '')
app.jinja_env.filters['slug'] = to_slug

def get_month_name(month_number):
    try: return calendar.month_name[int(month_number)]
    except (IndexError, ValueError): return ''
app.jinja_env.filters['month_name'] = get_month_name

def now_mexico():
    try: return datetime.now(ZoneInfo("America/Mexico_City"))
    except Exception:
        import pytz
        return datetime.now(pytz.timezone("America/Mexico_City"))

def get_business_date():
    now = now_mexico()
    if now.hour < 7 or (now.hour == 7 and now.minute < 30):
        return (now - timedelta(days=1)).date()
    return now.date()

def log_activity(action, details="", area_grupo=None, category="General", severity="Info"):
    try:
        log_entry = ActivityLog(
            timestamp=datetime.utcnow(), username=session.get('username', 'Sistema'), action=action,
            details=details, area_grupo=area_grupo, ip_address=request.remote_addr,
            category=category, severity=severity
        )
        db_session.add(log_entry)
        db_session.commit()
    except exc.SQLAlchemyError as e:
        db_session.rollback()
        print(f"Error al registrar actividad: {e}")

def get_hourly_target(pronostico_turno, turno_name):
    if not pronostico_turno or pronostico_turno <= 0: return 0
    num_horas = len(HORAS_TURNO.get(turno_name, []))
    if num_horas == 0: return 0
    return pronostico_turno / num_horas

def get_kpi_color_class(eficiencia):
    try:
        eficiencia = float(eficiencia)
        if eficiencia < 80: return 'kpi-red'
        if eficiencia < 95: return 'kpi-yellow'
        return 'kpi-green'
    except (ValueError, TypeError):
        return 'kpi-red'
app.jinja_env.filters['get_kpi_color'] = get_kpi_color_class

# ===============================================================
# === DECORADORES ===
# ===============================================================

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
                flash("Error de seguridad (CSRF Token inválido).", "danger")
                if request.is_json: return jsonify({'status': 'error', 'message': 'CSRF token missing or incorrect'}), 403
                return redirect(request.url)
        return f(*args, **kwargs)
    return decorated_function

# ===============================================================
# === RUTAS DE AUTENTICACIÓN Y NAVEGACIÓN PRINCIPAL ===
# ===============================================================

@app.route('/', methods=['GET', 'POST'])
def login():
    if 'loggedin' in session: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        user = db_session.query(Usuario).filter(Usuario.username == request.form.get('username')).first()
        if user and user.role and check_password_hash(user.password_hash, request.form.get('password')):
            session.clear()
            session.permanent = True
            session['loggedin'] = True
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role.nombre 
            session['nombre_completo'] = user.nombre_completo
            session['csrf_token'] = secrets.token_hex(16)
            log_activity("Inicio de sesión", f"Rol: {user.role.nombre}", 'Sistema', 'Autenticación', 'Info')
            return redirect(url_for('dashboard'))
        else:
            log_activity("Intento de inicio de sesión fallido", f"Intento con usuario: '{request.form.get('username')}'", 'Sistema', 'Seguridad', 'Warning')
            flash('Usuario o contraseña incorrectos.', 'danger')
    if 'csrf_token' not in session: session['csrf_token'] = secrets.token_hex(16)
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_activity("Cierre de sesión", "", 'Sistema', 'Autenticación', 'Info')
    session.clear()
    flash('Has cerrado sesión correctamente.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    role = session.get('role')
    if role in ['IHP', 'FHP']: return redirect(url_for('dashboard_group', group=role.lower()))
    if role == 'ADMIN': return redirect(url_for('dashboard_admin'))
    if role == 'PROGRAMA_LM': return redirect(url_for('programa_lm'))
    flash('No tienes un dashboard asignado.', 'warning')
    return redirect(url_for('login'))

# ===============================================================
# === LÓGICA DE DATOS DE PRODUCCIÓN ===
# ===============================================================

def get_group_performance(group_name, start_date_str, end_date_str=None):
    start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
    end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date() if end_date_str else start_date
    try:
        total_pronostico_areas = db_session.query(func.sum(Pronostico.valor_pronostico)).filter(Pronostico.grupo == group_name, Pronostico.fecha.between(start_date, end_date)).scalar() or 0
        total_pronostico_output = db_session.query(func.sum(OutputData.pronostico)).filter(OutputData.grupo == group_name, OutputData.fecha.between(start_date, end_date)).scalar() or 0
        total_producido_areas = db_session.query(func.sum(ProduccionCaptura.valor_producido)).filter(ProduccionCaptura.grupo == group_name, ProduccionCaptura.fecha.between(start_date, end_date)).scalar() or 0
        total_producido_output = db_session.query(func.sum(OutputData.output)).filter(OutputData.grupo == group_name, OutputData.fecha.between(start_date, end_date)).scalar() or 0
        total_pronostico = total_pronostico_areas + total_pronostico_output
        total_producido = total_producido_areas + total_producido_output
        eficiencia = (total_producido / total_pronostico * 100) if total_pronostico > 0 else 0
        return {'pronostico': f"{total_pronostico:,.0f}", 'producido': f"{total_producido:,.0f}", 'eficiencia': round(eficiencia, 2)}
    except exc.SQLAlchemyError as e:
        flash(f"Error al calcular el rendimiento del grupo: {e}", "danger")
        return {'pronostico': '0', 'producido': '0', 'eficiencia': 0}

def get_structured_capture_data(group_name, selected_date):
    nombres_turnos = NOMBRES_TURNOS_PRODUCCION
    data_to_render = {}
    try:
        areas_list = AREAS_IHP if group_name == 'IHP' else AREAS_FHP
        for area in [a for a in areas_list if a != 'Output']:
            data_to_render[area] = {}
            for turno in nombres_turnos:
                data_to_render[area][turno] = {'pronostico': '', 'razon_desviacion': None}
                for hora in HORAS_TURNO.get(turno, []):
                    data_to_render[area][turno][hora] = ''
        
        all_pronosticos = db_session.query(Pronostico).filter_by(fecha=selected_date, grupo=group_name).all()
        for p in all_pronosticos:
            if p.area in data_to_render and p.turno in data_to_render[p.area]:
                data_to_render[p.area][p.turno]['pronostico'] = p.valor_pronostico
                data_to_render[p.area][p.turno]['razon_desviacion'] = p.razon_desviacion
        
        all_produccion = db_session.query(ProduccionCaptura).filter_by(fecha=selected_date, grupo=group_name).all()
        for prod in all_produccion:
            for turno, horas in HORAS_TURNO.items():
                if prod.hora in horas and prod.area in data_to_render and turno in data_to_render[prod.area]:
                    data_to_render[prod.area][turno][prod.hora] = prod.valor_producido
                    break
    except exc.SQLAlchemyError as e:
        flash(f"Error al obtener datos estructurados para captura: {e}", "danger")
    return data_to_render

def get_output_data(group, date_str):
    selected_date = datetime.strptime(date_str, '%Y-%m-%d').date()
    try:
        output_row = db_session.query(OutputData).filter_by(fecha=selected_date, grupo=group).first()
        return {'pronostico': output_row.pronostico or 0, 'output': output_row.output or 0} if output_row else {'pronostico': 0, 'output': 0}
    except exc.SQLAlchemyError as e:
        flash(f"Error al obtener datos de Output: {e}", "danger")
        return {'pronostico': 0, 'output': 0}

def get_detailed_performance_data(selected_date):
    nombres_turnos = NOMBRES_TURNOS_PRODUCCION
    performance_data = {'IHP': {}, 'FHP': {}}
    all_areas = {'IHP': AREAS_IHP, 'FHP': AREAS_FHP}
    try:
        pronosticos = db_session.query(Pronostico).filter(Pronostico.fecha == selected_date).all()
        produccion_horas = db_session.query(ProduccionCaptura).filter(ProduccionCaptura.fecha == selected_date).all()
        for group, areas in all_areas.items():
            for area in [a for a in areas if a != 'Output']:
                performance_data[group][area] = {}
                for turno in nombres_turnos:
                    performance_data[group][area][turno] = {'pronostico': None, 'producido': 0, 'eficiencia': 0, 'horas': {hora: {'valor': None, 'class': ''} for hora in HORAS_TURNO.get(turno, [])}}
        for p in pronosticos:
            if p.grupo in performance_data and p.area in performance_data[p.grupo] and p.turno in performance_data[p.grupo][p.area]:
                performance_data[p.grupo][p.area][p.turno]['pronostico'] = p.valor_pronostico
        for prod in produccion_horas:
            for turno_name, horas_del_turno in HORAS_TURNO.items():
                if prod.hora in horas_del_turno and prod.grupo in performance_data and prod.area in performance_data[prod.grupo] and turno_name in performance_data[prod.grupo][prod.area]:
                    valor = prod.valor_producido or 0
                    performance_data[prod.grupo][prod.area][turno_name]['horas'][prod.hora]['valor'] = valor
                    performance_data[prod.grupo][prod.area][turno_name]['producido'] += valor
                    break
        for group in performance_data:
            for area in performance_data[group]:
                for turno_name, turno_data in performance_data[group][area].items():
                    pronostico_turno = turno_data.get('pronostico')
                    if pronostico_turno is not None and pronostico_turno > 0:
                        turno_data['eficiencia'] = round((turno_data.get('producido', 0) / pronostico_turno) * 100, 1)
                        hourly_target = get_hourly_target(pronostico_turno, turno_name)
                        for hora, hora_data in turno_data.get('horas', {}).items():
                            prod_hora = hora_data.get('valor')
                            if prod_hora is not None and hourly_target > 0:
                                hora_data['class'] = 'text-success font-weight-bold' if prod_hora >= hourly_target else 'text-warning font-weight-bold'
                    else:
                        turno_data['eficiencia'] = 0
    except exc.SQLAlchemyError as e:
        flash(f"Error al generar datos detallados del dashboard: {e}", "danger")
    return performance_data

# ===============================================================
# === RUTAS DE DASHBOARD Y PRODUCCIÓN ===
# ===============================================================

@app.route('/dashboard/admin')
@login_required
@role_required(['ADMIN'])
def dashboard_admin():
    selected_date_str = request.args.get('fecha', get_business_date().strftime('%Y-%m-%d'))
    try: selected_date = datetime.strptime(selected_date_str, '%Y-%m-%d').date()
    except ValueError: selected_date, selected_date_str = get_business_date(), get_business_date().strftime('%Y-%m-%d'); flash("Formato de fecha inválido.", "warning")
    
    ihp_kpi_data = get_group_performance('IHP', selected_date_str)
    fhp_kpi_data = get_group_performance('FHP', selected_date_str)
    total_pronostico = (int(ihp_kpi_data['pronostico'].replace(',', '')) + int(fhp_kpi_data['pronostico'].replace(',', '')))
    total_producido = (int(ihp_kpi_data['producido'].replace(',', '')) + int(fhp_kpi_data['producido'].replace(',', '')))
    total_eficiencia = (total_producido / total_pronostico * 100) if total_pronostico > 0 else 0
    global_kpis = {'pronostico': f"{total_pronostico:,.0f}", 'producido': f"{total_producido:,.0f}", 'eficiencia': round(total_eficiencia, 2)}
    
    performance_data = get_detailed_performance_data(selected_date)
    output_data_ihp = get_output_data('IHP', selected_date_str)
    output_data_fhp = get_output_data('FHP', selected_date_str)
    period_label = f"Hoy ({selected_date_str})" if selected_date == get_business_date() else f"Día: {selected_date_str}"
    
    return render_template('dashboard_admin.html', period_label=period_label, selected_date=selected_date_str, global_kpis=global_kpis, ihp_data=ihp_kpi_data, fhp_data=fhp_kpi_data, performance_data=performance_data, output_data_ihp=output_data_ihp, output_data_fhp=output_data_fhp, nombres_turnos=NOMBRES_TURNOS_PRODUCCION, horas_turno=HORAS_TURNO, AREAS_IHP=AREAS_IHP, AREAS_FHP=AREAS_FHP)

@app.route('/dashboard/<group>')
@login_required
def dashboard_group(group):
    group_upper = group.upper()
    if group_upper not in ['IHP', 'FHP']: abort(404)
    if session.get('role') not in [group_upper, 'ADMIN']: flash('No tienes permiso para ver este dashboard.', 'danger'); return redirect(url_for('dashboard'))
    
    today_str = get_business_date().strftime('%Y-%m-%d')
    yesterday_str = (get_business_date() - timedelta(days=1)).strftime('%Y-%m-%d')
    summary_today = get_group_performance(group_upper, today_str)
    summary_yesterday = get_group_performance(group_upper, yesterday_str)
    
    prod_today_num = int(summary_today['producido'].replace(',', ''))
    prod_yesterday_num = int(summary_yesterday['producido'].replace(',', ''))
    summary_today['trend'] = 'up' if prod_today_num > prod_yesterday_num else 'down' if prod_today_num < prod_yesterday_num else 'stable'
    
    all_performance_data = get_detailed_performance_data(get_business_date())
    group_performance_data = all_performance_data.get(group_upper, {})
    output_data = get_output_data(group_upper, today_str)
    areas_list = [a for a in (AREAS_IHP if group_upper == 'IHP' else AREAS_FHP) if a != 'Output']
    
    return render_template('dashboard_group.html', summary=summary_today, areas=areas_list, nombres_turnos=NOMBRES_TURNOS_PRODUCCION, horas_turno=HORAS_TURNO, today=today_str, group_name=group_upper, performance_data=group_performance_data, output_data=output_data)

@app.route('/registro/<group>')
@login_required
def registro(group):
    group_upper = group.upper()
    if group_upper not in ['IHP', 'FHP']: abort(404)
    if session.get('role') not in [group_upper, 'ADMIN']: flash('No tienes permiso para ver este registro.', 'danger'); return redirect(url_for('dashboard'))
    
    selected_date_str = request.args.get('fecha', get_business_date().strftime('%Y-%m-%d'))
    try: selected_date = datetime.strptime(selected_date_str, '%Y-%m-%d').date()
    except ValueError: selected_date, selected_date_str = get_business_date(), get_business_date().strftime('%Y-%m-%d'); flash("Formato de fecha inválido.", "warning")
    
    areas_list = AREAS_IHP if group_upper == 'IHP' else AREAS_FHP
    all_performance_data = get_detailed_performance_data(selected_date)
    group_performance_data = all_performance_data.get(group_upper, {})
    output_data = get_output_data(group_upper, selected_date_str)
    meta_produccion = 4830 if group_upper == 'FHP' else 879
    totals = {'pronostico': 0, 'producido': 0}
    for area, turnos in group_performance_data.items():
        for turno, data in turnos.items():
            if data.get('pronostico') is not None: totals['pronostico'] += data.get('pronostico', 0)
            totals['producido'] += data.get('producido', 0)
    totals['pronostico'] += output_data.get('pronostico', 0)
    totals['producido'] += output_data.get('output', 0)
    totals['eficiencia'] = (totals['producido'] / totals['pronostico'] * 100) if totals['pronostico'] > 0 else 0
    
    return render_template('registro_group.html', selected_date=selected_date_str, performance_data=group_performance_data, areas=areas_list, nombres_turnos=NOMBRES_TURNOS_PRODUCCION, output_data=output_data, group_name=group_upper, totals=totals, meta=meta_produccion, horas_turno=HORAS_TURNO)

@app.route('/reportes')
@login_required
@role_required(['ADMIN', 'IHP', 'FHP'])
def reportes():
    user_role, is_admin = session.get('role'), session.get('role') == 'ADMIN'
    default_group = user_role if user_role in ['IHP', 'FHP'] else 'IHP'
    group = request.args.get('group', default_group)
    if not is_admin: group = user_role
    
    today = now_mexico()
    year, month = request.args.get('year', today.year, type=int), request.args.get('month', today.month, type=int)
    efficiency_data, areas_data = {'labels': [], 'data': []}, {'labels': [], 'data': []}
    
    try:
        num_days = calendar.monthrange(year, month)[1]
        for day in range(1, num_days + 1):
            date_str = f"{year}-{month:02d}-{day:02d}"
            performance_day = get_group_performance(group, date_str)
            eficiencia = performance_day.get('eficiencia', 0)
            if eficiencia > 0: efficiency_data['labels'].append(f"{day}/{month}"); efficiency_data['data'].append(eficiencia)
    except exc.SQLAlchemyError as e: flash(f"Error al calcular la tendencia de eficiencia: {e}", "danger")
    
    try:
        start_of_month, end_of_month = datetime(year, month, 1).date(), (datetime(year, month, 1).replace(day=28) + timedelta(days=4)).replace(day=1) - timedelta(days=1)
        areas_list = [area for area in (AREAS_IHP if group == 'IHP' else AREAS_FHP) if area != 'Output']
        for area in areas_list:
            produccion_area = db_session.query(func.sum(ProduccionCaptura.valor_producido)).filter(ProduccionCaptura.grupo == group, ProduccionCaptura.area == area, ProduccionCaptura.fecha.between(start_of_month, end_of_month)).scalar() or 0
            if produccion_area > 0: areas_data['labels'].append(area); areas_data['data'].append(produccion_area)
        output_mes = db_session.query(func.sum(OutputData.output)).filter(OutputData.grupo == group, OutputData.fecha.between(start_of_month, end_of_month)).scalar() or 0
        if output_mes > 0: areas_data['labels'].append('Output'); areas_data['data'].append(output_mes)
    except exc.SQLAlchemyError as e: flash(f"Error al calcular la comparación de áreas: {e}", "danger")
    
    return render_template('reportes.html', group=group, selected_year=year, selected_month=month, is_admin=is_admin, efficiency_data=efficiency_data, areas_data=areas_data)

@app.route('/captura/<group>', methods=['GET', 'POST'])
@login_required
@csrf_required
def captura(group):
    group_upper = group.upper()
    if group_upper not in ['IHP', 'FHP']: abort(404)
    if session.get('role') not in [group_upper, 'ADMIN']: flash('No tienes permiso para capturar datos.', 'danger'); return redirect(url_for('dashboard'))
    
    nombres_turnos = NOMBRES_TURNOS_PRODUCCION
    areas_list = AREAS_IHP if group_upper == 'IHP' else AREAS_FHP
    
    if request.method == 'POST':
        selected_date_str = request.form.get('fecha')
        selected_date = datetime.strptime(selected_date_str, '%Y-%m-%d').date()
        now_dt, changes_detected = now_mexico(), False
        try:
            for area in [a for a in areas_list if a != 'Output']:
                for turno in nombres_turnos:
                    new_val_str = request.form.get(f'pronostico_{to_slug(area)}_{to_slug(turno)}')
                    if new_val_str and new_val_str.isdigit():
                        new_val = int(new_val_str)
                        existing = db_session.query(Pronostico).filter_by(fecha=selected_date, grupo=group_upper, area=area, turno=turno).first()
                        if existing:
                            if (existing.valor_pronostico or 0) != new_val:
                                old_val = existing.valor_pronostico; existing.valor_pronostico = new_val; changes_detected = True
                                log_activity("Modificación Pronóstico", f"Area: {area}, Turno: {turno}. Valor: {old_val} -> {new_val}", group_upper, 'Datos', 'Info')
                        else:
                            db_session.add(Pronostico(fecha=selected_date, grupo=group_upper, area=area, turno=turno, valor_pronostico=new_val)); changes_detected = True
                            log_activity("Creación Pronóstico", f"Area: {area}, Turno: {turno}. Valor: {new_val}", group_upper, 'Datos', 'Info')
            for area in [a for a in areas_list if a != 'Output']:
                for turno in nombres_turnos:
                    for hora in HORAS_TURNO.get(turno, []):
                        new_val_str = request.form.get(f'produccion_{to_slug(area)}_{hora}')
                        if new_val_str and new_val_str.isdigit():
                            new_val = int(new_val_str)
                            existing = db_session.query(ProduccionCaptura).filter_by(fecha=selected_date, grupo=group_upper, area=area, hora=hora).first()
                            if existing:
                                if (existing.valor_producido or 0) != new_val:
                                    old_val = existing.valor_producido; existing.valor_producido = new_val; existing.usuario_captura = session.get('username'); existing.fecha_captura = now_dt; changes_detected = True
                                    log_activity("Modificación Producción", f"Area: {area}, Hora: {hora}. Valor: {old_val} -> {new_val}", group_upper, 'Datos', 'Info')
                            else:
                                db_session.add(ProduccionCaptura(fecha=selected_date, grupo=group_upper, area=area, hora=hora, valor_producido=new_val, usuario_captura=session.get('username'), fecha_captura=now_dt)); changes_detected = True
                                log_activity("Creación Producción", f"Area: {area}, Hora: {hora}. Valor: {new_val}", group_upper, 'Datos', 'Info')
            existing_output = db_session.query(OutputData).filter_by(fecha=selected_date, grupo=group_upper).first()
            new_pron_out, new_prod_out = request.form.get('pronostico_output'), request.form.get('produccion_output')
            if existing_output:
                if new_pron_out and new_pron_out.isdigit() and int(new_pron_out) != (existing_output.pronostico or 0): existing_output.pronostico = int(new_pron_out); changes_detected = True
                if new_prod_out and new_prod_out.isdigit() and int(new_prod_out) != (existing_output.output or 0): existing_output.output = int(new_prod_out); changes_detected = True
            elif (new_pron_out and new_pron_out.isdigit()) or (new_prod_out and new_prod_out.isdigit()):
                db_session.add(OutputData(fecha=selected_date, grupo=group_upper, pronostico=int(new_pron_out or 0), output=int(new_prod_out or 0), usuario_captura=session.get('username'), fecha_captura=now_dt)); changes_detected = True
            db_session.commit()
            if changes_detected: flash('Cambios guardados exitosamente.', 'success')
            else: flash('No se detectaron cambios.', 'info')
        except exc.SQLAlchemyError as e:
            db_session.rollback(); flash(f"Error al guardar: {e}", 'danger')
        return redirect(url_for('captura', group=group, fecha=selected_date_str))
        
    selected_date_str = request.args.get('fecha', get_business_date().strftime('%Y-%m-%d'))
    try: selected_date = datetime.strptime(selected_date_str, '%Y-%m-%d').date()
    except ValueError: selected_date, selected_date_str = get_business_date(), get_business_date().strftime('%Y-%m-%d'); flash("Formato de fecha inválido.", "warning")
    data_for_template = get_structured_capture_data(group_upper, selected_date)
    output_data = get_output_data(group_upper, selected_date_str)
    return render_template('captura_group.html', areas=areas_list, horas_turno=HORAS_TURNO, nombres_turnos=nombres_turnos, selected_date=selected_date_str, data=data_for_template, output_data=output_data, group_name=group_upper)

# ===============================================================
# === NUEVA RUTA CORREGIDA/AÑADIDA ===
# ===============================================================
@app.route('/submit_reason', methods=['POST'])
@login_required
@csrf_required
def submit_reason():
    """
    Recibe una justificación de desviación vía AJAX desde la página de captura 
    y la guarda en la base de datos.
    """
    try:
        date_str = request.form.get('date')
        area = request.form.get('area')
        group = request.form.get('group')
        turno_name = request.form.get('turno_name')
        reason = request.form.get('reason')
        
        selected_date = datetime.strptime(date_str, '%Y-%m-%d').date()

        pronostico_entry = db_session.query(Pronostico).filter_by(
            fecha=selected_date,
            grupo=group.upper(),
            area=area,
            turno=turno_name
        ).first()

        if pronostico_entry:
            pronostico_entry.razon_desviacion = reason
            pronostico_entry.usuario_razon = session.get('username')
            pronostico_entry.fecha_razon = datetime.utcnow()
            pronostico_entry.status = 'Nuevo'
            db_session.commit()
            log_activity("Justificación Desviación", f"Area: {area}, Turno: {turno_name}", group, 'Datos', 'Info')
            return jsonify({'status': 'success', 'message': 'La razón ha sido guardada exitosamente.'})
        else:
            return jsonify({'status': 'error', 'message': 'No se encontró el registro de pronóstico para actualizar.'}), 404
            
    except Exception as e:
        db_session.rollback()
        log_activity("Error Justificación", str(e), "Sistema", "Error", "Critical")
        print(f"Error al guardar razón: {e}")
        return jsonify({'status': 'error', 'message': f'Ocurrió un error en el servidor: {e}'}), 500

@app.route('/export_excel/<group>')
@login_required
def export_excel(group):
    group_upper = group.upper()
    if group_upper not in ['IHP', 'FHP']: abort(404)
    if session.get('role') not in [group_upper, 'ADMIN']: flash('No tienes permiso para exportar estos datos.', 'danger'); return redirect(url_for('dashboard'))
    
    selected_date_str = request.args.get('fecha', get_business_date().strftime('%Y-%m-%d'))
    selected_date = datetime.strptime(selected_date_str, '%Y-%m-%d').date()
    all_performance_data = get_detailed_performance_data(selected_date)
    production_data = all_performance_data.get(group_upper, {})
    output_data = get_output_data(group_upper, selected_date_str)
    
    meta_produccion, nombres_turnos = (4830 if group_upper == 'FHP' else 879), NOMBRES_TURNOS_PRODUCCION
    records = []
    
    for area, turnos_data in production_data.items():
        record, total_pronostico_area, total_producido_area = {'Area': area}, 0, 0
        for turno_name, data in turnos_data.items():
            if turno_name in nombres_turnos:
                pronostico, producido = data.get('pronostico', 0), data.get('producido', 0)
                record[f'Pronóstico {turno_name}'], record[f'Producido {turno_name}'] = pronostico, producido
                total_pronostico_area += pronostico or 0; total_producido_area += producido or 0
        record['Pronóstico Total'], record['Producido Total'] = total_pronostico_area, total_producido_area
        records.append(record)
        
    if output_data and (output_data.get('pronostico') or output_data.get('output')):
        output_record = {'Area': 'Output'}
        for turno in nombres_turnos: output_record[f'Pronóstico {turno}'], output_record[f'Producido {turno}'] = None, None
        output_record['Pronóstico Total'], output_record['Producido Total'] = output_data.get('pronostico', 0), output_data.get('output', 0)
        records.append(output_record)
    
    if not records: flash('No hay datos para exportar en la fecha seleccionada.', 'warning'); return redirect(url_for('registro', group=group_upper, fecha=selected_date_str))
    
    df = pd.DataFrame(records)
    cols = ['Area']
    for turno in nombres_turnos: cols.extend([f'Pronóstico {turno}', f'Producido {turno}'])
    cols.extend(['Pronóstico Total', 'Producido Total'])
    df = df.reindex(columns=cols)
    df['Meta'] = meta_produccion
    
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='RegistroProduccion', startrow=1)
        workbook, worksheet = writer.book, writer.sheets['RegistroProduccion']
        header_format, title_format = workbook.add_format({'bold': True, 'text_wrap': True, 'valign': 'top', 'fg_color': '#D7E4BC', 'border': 1}), workbook.add_format({'bold': True, 'font_size': 14})
        worksheet.write('A1', f'Reporte de Producción - {group_upper} ({selected_date_str})', title_format)
        for col_num, value in enumerate(df.columns.values): worksheet.write(1, col_num, value, header_format)
        worksheet.set_column('A:A', 20); worksheet.set_column('B:Z', 15)
        num_rows = len(df)
        column_chart, line_chart = workbook.add_chart({'type': 'column'}), workbook.add_chart({'type': 'line'})
        column_chart.add_series({'name': ['RegistroProduccion', 1, df.columns.get_loc('Producido Total')], 'categories': ['RegistroProduccion', 2, 0, num_rows + 1, 0], 'values': ['RegistroProduccion', 2, df.columns.get_loc('Producido Total'), num_rows + 1, df.columns.get_loc('Producido Total')], 'fill': {'color': '#24b817'}, 'border': {'color': '#1c8c11'}})
        line_chart.add_series({'name': ['RegistroProduccion', 1, df.columns.get_loc('Meta')], 'categories': ['RegistroProduccion', 2, 0, num_rows + 1, 0], 'values': ['RegistroProduccion', 2, df.columns.get_loc('Meta'), num_rows + 1, df.columns.get_loc('Meta')], 'line': {'color': 'red', 'width': 2.5, 'dash_type': 'solid'}})
        column_chart.combine(line_chart)
        column_chart.set_title({'name': f'Producción por Área vs. Meta Diaria ({group_upper})'}); column_chart.set_x_axis({'name': 'Área de Producción'}); column_chart.set_y_axis({'name': 'Unidades Producidas'}); column_chart.set_size({'width': 720, 'height': 480})
        worksheet.insert_chart(f'A{num_rows + 5}', column_chart)
    output.seek(0)
    return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', as_attachment=True, download_name=f'produccion_{group_upper}_{selected_date_str}.xlsx')

# ===============================================================
# === RUTAS PARA PROGRAMA LM, GESTIÓN Y ACCIONES ===
# ===============================================================

# ===============================================================
# === NUEVA RUTA CORREGIDA/AÑADIDA ===
# ===============================================================
@app.route('/programa_lm')
@login_required
@role_required(['ADMIN', 'PROGRAMA_LM'])
def programa_lm():
    """
    Renderiza la tabla principal del Programa LM, obteniendo todas las órdenes,
    columnas y datos de celdas asociados.
    """
    try:
        # Carga las órdenes y, de forma eficiente, sus celdas asociadas de una sola vez
        ordenes = db_session.query(OrdenLM).options(joinedload(OrdenLM.celdas)).order_by(OrdenLM.timestamp.desc()).all()
        columnas = db_session.query(ColumnaLM).order_by(ColumnaLM.orden, ColumnaLM.nombre).all()
        
        # Estructura los datos de las celdas en un diccionario para un acceso rápido en la plantilla
        # El formato es: { orden_id: { columna_id: valor_celda } }
        datos_celdas = {
            orden.id: {celda.columna_id: celda.valor for celda in orden.celdas}
            for orden in ordenes
        }

        return render_template(
            'programa_lm.html', 
            ordenes=ordenes, 
            columnas=columnas, 
            datos=datos_celdas
        )
    except exc.SQLAlchemyError as e:
        flash(f"Error crítico al cargar el programa LM: {e}", "danger")
        log_activity("Error DB Programa LM", str(e), "PROGRAMA_LM", "Sistema", "Critical")
        return redirect(url_for('dashboard'))

@app.route('/programa_lm/update_cell', methods=['POST'])
@login_required
@csrf_required
def update_cell_lm():
    try:
        data = request.json
        orden_id, columna_id, valor = int(data.get('orden_id')), int(data.get('columna_id')), data.get('valor', '').strip()
        columna = db_session.query(ColumnaLM).get(columna_id)
        if not columna: return jsonify({'status': 'error', 'message': 'Columna no encontrada'}), 404
        if session['role'] != 'ADMIN' and not columna.editable_por_lm:
            log_activity("Acceso Denegado", f"Intento de editar celda LM protegida. Orden ID: {orden_id}, Columna: {columna.nombre}", "PROGRAMA_LM", "Seguridad", "Warning")
            return jsonify({'status': 'error', 'message': 'No tienes permiso para editar esta celda.'}), 403
        celda = db_session.query(DatoCeldaLM).filter_by(orden_id=orden_id, columna_id=columna_id).first()
        if celda:
            if not valor: db_session.delete(celda)
            else: celda.valor = valor
        elif valor: db_session.add(DatoCeldaLM(orden_id=orden_id, columna_id=columna_id, valor=valor))
        db_session.commit()
        log_activity("Edición Celda LM", f"Orden ID: {orden_id}, Columna: {columna.nombre}, Valor: '{valor}'", "PROGRAMA_LM", "Datos", "Info")
        return jsonify({'status': 'success', 'message': 'Celda actualizada'})
    except Exception as e:
        db_session.rollback(); print(f"Error al actualizar celda: {e}"); return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/programa_lm/add_row', methods=['POST'])
@login_required
@role_required(['ADMIN'])
@csrf_required
def add_row_lm():
    wip_order, item, qty = request.form.get('wip_order'), request.form.get('item'), request.form.get('qty', 1, type=int)
    if not wip_order: flash("El campo 'WIP Order' es obligatorio.", "danger")
    elif db_session.query(OrdenLM).filter_by(wip_order=wip_order).first(): flash(f"La orden WIP '{wip_order}' ya existe.", "warning")
    else:
        db_session.add(OrdenLM(wip_order=wip_order, item=item, qty=qty)); db_session.commit()
        log_activity("Creación Fila LM", f"Nueva orden WIP creada: {wip_order}", "ADMIN", "Datos", "Info")
        flash("Nueva orden agregada exitosamente.", "success")
    return redirect(url_for('programa_lm'))

@app.route('/programa_lm/add_column', methods=['POST'])
@login_required
@role_required(['ADMIN'])
@csrf_required
def add_column_lm():
    nombre_columna = request.form.get('nombre_columna')
    if not nombre_columna: flash("El nombre de la columna es obligatorio.", "danger")
    elif db_session.query(ColumnaLM).filter_by(nombre=nombre_columna).first(): flash(f"La columna '{nombre_columna}' ya existe.", "warning")
    else:
        db_session.add(ColumnaLM(nombre=nombre_columna, editable_por_lm=True)); db_session.commit()
        log_activity("Creación Columna LM", f"Nueva columna creada: {nombre_columna}", "ADMIN", "Datos", "Info")
        flash("Nueva columna agregada exitosamente.", "success")
    return redirect(url_for('programa_lm'))
@app.route('/programa_lm/delete_column/<int:columna_id>', methods=['POST'])
@login_required
@role_required(['ADMIN'])
@csrf_required
def delete_column_lm(columna_id):
    """
    Elimina una columna completa del Programa LM y todos sus datos asociados.
    Solo accesible para Administradores.
    """
    try:
        columna_a_eliminar = db_session.query(ColumnaLM).get(columna_id)
        
        if columna_a_eliminar:
            nombre_columna = columna_a_eliminar.nombre
            
            # Gracias al 'cascade' en el modelo, al borrar la columna,
            # SQLAlchemy también borrará todos los DatoCeldaLM asociados.
            db_session.delete(columna_a_eliminar)
            db_session.commit()
            
            log_activity("Eliminación Columna LM", f"Columna '{nombre_columna}' (ID: {columna_id}) eliminada.", "ADMIN", "Seguridad", "Critical")
            flash(f"La columna '{nombre_columna}' y todos sus datos han sido eliminados exitosamente.", "success")
        else:
            flash("La columna que intentas eliminar no existe.", "danger")
            
    except exc.SQLAlchemyError as e:
        db_session.rollback()
        flash(f"Error al eliminar la columna: {e}", "danger")
        log_activity("Error Eliminación Columna LM", f"Error al intentar borrar columna ID {columna_id}: {e}", "ADMIN", "Error", "Critical")

    return redirect(url_for('programa_lm'))

@app.route('/centro_acciones')
@login_required
@role_required(['ADMIN'])
def centro_acciones():
    if request.args.get('limpiar'): session.pop('acciones_filtros', None); return redirect(url_for('centro_acciones'))
    filtros = session.get('acciones_filtros', {})
    if not request.args: filtros = {'status': 'Pendientes', 'tipo': 'Todos', 'grupo': 'Todos'}
    elif any(arg in request.args for arg in ['fecha_inicio', 'fecha_fin', 'grupo', 'tipo', 'status']):
        filtros = {'fecha_inicio': request.args.get('fecha_inicio'), 'fecha_fin': request.args.get('fecha_fin'), 'grupo': request.args.get('grupo'), 'tipo': request.args.get('tipo', 'Todos'), 'status': request.args.get('status', 'Pendientes')}
    session['acciones_filtros'] = filtros
    items, query_desviaciones, query_solicitudes = [], db_session.query(Pronostico, Usuario.nombre_completo).join(Usuario, Pronostico.usuario_razon == Usuario.username, isouter=True).filter(Pronostico.razon_desviacion.isnot(None), Pronostico.razon_desviacion != ''), db_session.query(SolicitudCorreccion, Usuario.nombre_completo).join(Usuario, SolicitudCorreccion.usuario_solicitante == Usuario.username, isouter=True)
    if filtros.get('fecha_inicio'): query_desviaciones = query_desviaciones.filter(Pronostico.fecha >= datetime.strptime(filtros['fecha_inicio'], '%Y-%m-%d').date()); query_solicitudes = query_solicitudes.filter(SolicitudCorreccion.fecha_problema >= datetime.strptime(filtros['fecha_inicio'], '%Y-%m-%d').date())
    if filtros.get('fecha_fin'): query_desviaciones = query_desviaciones.filter(Pronostico.fecha <= datetime.strptime(filtros['fecha_fin'], '%Y-%m-%d').date()); query_solicitudes = query_solicitudes.filter(SolicitudCorreccion.fecha_problema <= datetime.strptime(filtros['fecha_fin'], '%Y-%m-%d').date())
    if filtros.get('grupo') and filtros.get('grupo') != 'Todos': query_desviaciones = query_desviaciones.filter(Pronostico.grupo == filtros['grupo']); query_solicitudes = query_solicitudes.filter(SolicitudCorreccion.grupo == filtros['grupo'])
    status_filter = filtros.get('status')
    if status_filter == 'Pendientes': query_desviaciones, query_solicitudes = query_desviaciones.filter(Pronostico.status == 'Nuevo'), query_solicitudes.filter(SolicitudCorreccion.status == 'Pendiente')
    elif status_filter and status_filter != 'Todos': query_desviaciones, query_solicitudes = query_desviaciones.filter(Pronostico.status == status_filter), query_solicitudes.filter(SolicitudCorreccion.status == status_filter)
    if filtros.get('tipo', 'Todos') in ['Todos', 'Desviacion']:
        for d, nombre in query_desviaciones.all(): items.append({'id': d.id, 'tipo': 'Desviación', 'timestamp': d.fecha_razon, 'fecha_evento': d.fecha, 'grupo': d.grupo, 'area': d.area, 'turno': d.turno, 'usuario': nombre or d.usuario_razon, 'detalles': d.razon_desviacion, 'status': d.status})
    if filtros.get('tipo', 'Todos') in ['Todos', 'Correccion']:
        for s, nombre in query_solicitudes.all(): items.append({'id': s.id, 'tipo': f"Corrección ({s.tipo_error})", 'timestamp': s.timestamp, 'fecha_evento': s.fecha_problema, 'grupo': s.grupo, 'area': s.area, 'turno': s.turno, 'usuario': nombre or s.usuario_solicitante, 'detalles': s.descripcion, 'status': s.status})
    items.sort(key=lambda x: x['timestamp'] if x['timestamp'] else datetime.min, reverse=True)
    return render_template('centro_acciones.html', items=items, filtros=filtros)

@app.route('/solicitar_correccion', methods=['POST'])
@login_required
@csrf_required
def solicitar_correccion():
    try:
        db_session.add(SolicitudCorreccion(usuario_solicitante=session.get('username'), fecha_problema=datetime.strptime(request.form.get('fecha_problema'), '%Y-%m-%d').date(), grupo=request.form.get('grupo'), area=request.form.get('area'), turno=request.form.get('turno'), tipo_error=request.form.get('tipo_error'), descripcion=request.form.get('descripcion')))
        log_activity(f"Solicitud Corrección ({request.form.get('tipo_error')})", f"Area: {request.form.get('area')}, Turno: {request.form.get('turno')}", request.form.get('grupo'), 'Datos', 'Warning')
        db_session.commit()
        return jsonify({'status': 'success', 'message': 'Tu solicitud ha sido enviada.'})
    except Exception as e:
        db_session.rollback(); return jsonify({'status': 'error', 'message': f'Ocurrió un error: {e}'}), 500

@app.route('/update_reason_status/<int:reason_id>', methods=['POST'])
@login_required
@role_required(['ADMIN'])
@csrf_required
def update_reason_status(reason_id):
    reason = db_session.query(Pronostico).get(reason_id)
    if reason and request.form.get('status'):
        old, new = reason.status, request.form.get('status'); reason.status = new
        log_activity("Cambio Estado (Desviación)", f"ID Razón: {reason.id}. Estado: '{old}' -> '{new}'.", reason.grupo, 'Datos', 'Info')
        db_session.commit(); flash(f"Estado actualizado a '{new}'.", 'success')
    else: flash("No se pudo actualizar el estado.", 'danger')
    return redirect(url_for('centro_acciones'))

@app.route('/update_solicitud_status/<int:solicitud_id>', methods=['POST'])
@login_required
@role_required(['ADMIN'])
@csrf_required
def update_solicitud_status(solicitud_id):
    solicitud = db_session.query(SolicitudCorreccion).get(solicitud_id)
    if solicitud:
        solicitud.status, solicitud.admin_username, solicitud.admin_notas, solicitud.fecha_resolucion = request.form.get('status'), session.get('username'), request.form.get('admin_notas'), datetime.utcnow()
        log_activity("Cambio Estado (Corrección)", f"ID Solicitud: {solicitud.id}. Estado: '{solicitud.status}' -> '{request.form.get('status')}'.", solicitud.grupo, 'Datos', 'Info')
        db_session.commit(); flash('Estado de la solicitud actualizado.', 'success')
    else: flash('No se encontró la solicitud.', 'danger')
    return redirect(url_for('centro_acciones'))

@app.route('/manage_users', methods=['GET', 'POST'])
@login_required
@role_required(['ADMIN'])
@csrf_required
def manage_users():
    if request.method == 'POST' and request.form.get('form_type') == 'create_user':
        username, password, role_id, turno_id, nombre, cargo = request.form.get('username'), request.form.get('password'), request.form.get('role_id'), request.form.get('turno_id'), request.form.get('nombre_completo'), request.form.get('cargo')
        if not all([username, password, role_id, nombre, cargo]): flash('Todos los campos son obligatorios.', 'warning')
        elif db_session.query(Usuario).filter_by(username=username).first(): flash(f"El usuario '{username}' ya existe.", 'danger')
        else:
            db_session.add(Usuario(username=username, password=password, role_id=role_id, nombre_completo=nombre, cargo=cargo, turno_id=turno_id if turno_id else None)); db_session.commit()
            rol = db_session.query(Rol).get(role_id)
            log_activity("Creación de usuario", f"Usuario '{username}' ({nombre}) creado con rol '{rol.nombre}'.", 'ADMIN', 'Seguridad', 'Info')
            flash(f"Usuario '{username}' creado exitosamente.", 'success')
        return redirect(url_for('manage_users'))
    if request.args.get('limpiar'): session.pop('user_filtros', None); return redirect(url_for('manage_users'))
    filtros, query = {}, db_session.query(Usuario).join(Rol).outerjoin(Turno)
    if any(arg in request.args for arg in ['username', 'nombre_completo', 'role_id', 'turno_id']):
        filtros = {'username': request.args.get('username', ''), 'nombre_completo': request.args.get('nombre_completo', ''), 'role_id': request.args.get('role_id', ''), 'turno_id': request.args.get('turno_id', '')}
        session['user_filtros'] = filtros
    elif 'user_filtros' in session: filtros = session.get('user_filtros', {})
    if filtros.get('username'): query = query.filter(Usuario.username.ilike(f"%{filtros['username']}%"))
    if filtros.get('nombre_completo'): query = query.filter(Usuario.nombre_completo.ilike(f"%{filtros['nombre_completo']}%"))
    if filtros.get('role_id'): query = query.filter(Rol.id == filtros['role_id'])
    if filtros.get('turno_id'): query = query.filter(Turno.id == filtros['turno_id'])
    users = query.order_by(Usuario.id).all()
    all_roles, all_turnos = db_session.query(Rol).order_by(Rol.nombre).all(), db_session.query(Turno).order_by(Turno.nombre).all()
    return render_template('manage_users.html', users=users, all_roles=all_roles, all_turnos=all_turnos, filtros=filtros)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required(['ADMIN'])
@csrf_required
def edit_user(user_id):
    user = db_session.query(Usuario).get_or_404(user_id)
    if request.method == 'POST':
        new_username = request.form.get('username')
        if new_username != user.username and db_session.query(Usuario).filter_by(username=new_username).first(): flash(f"El usuario '{new_username}' ya existe.", 'danger')
        else: user.username = new_username
        user.nombre_completo, user.cargo, user.role_id, user.turno_id = request.form.get('nombre_completo'), request.form.get('cargo'), request.form.get('role_id'), request.form.get('turno_id') or None
        if request.form.get('password'): user.password_hash = generate_password_hash(request.form.get('password'))
        try:
            db_session.commit()
            log_activity("Edición de usuario", f"Datos del usuario ID {user.id} ({user.username}) actualizados.", 'ADMIN', 'Seguridad', 'Warning')
            flash('Usuario actualizado correctamente.', 'success')
            return redirect(url_for('manage_users'))
        except exc.IntegrityError as e:
            db_session.rollback(); flash(f"Error de integridad: {e}", 'danger')
    all_roles, all_turnos = db_session.query(Rol).order_by(Rol.nombre).all(), db_session.query(Turno).order_by(Turno.nombre).all()
    return render_template('edit_user.html', user=user, all_roles=all_roles, all_turnos=all_turnos)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@role_required(['ADMIN'])
@csrf_required
def delete_user(user_id):
    if user_id == session.get('user_id'): flash('No puedes eliminar tu propia cuenta.', 'danger')
    else:
        user = db_session.query(Usuario).get(user_id)
        if user:
            log_activity("Eliminación de usuario", f"Usuario '{user.username}' (ID: {user_id}) fue eliminado.", 'ADMIN', 'Seguridad', 'Critical')
            db_session.delete(user); db_session.commit(); flash('Usuario eliminado exitosamente.', 'success')
        else: flash('El usuario no existe.', 'danger')
    return redirect(url_for('manage_users'))

@app.route('/activity_log')
@login_required
@role_required(['ADMIN'])
def activity_log():
    if request.args.get('limpiar'): session.pop('log_filtros', None); return redirect(url_for('activity_log'))
    filtros = session.get('log_filtros', {}) if not request.args else {'fecha_inicio': request.args.get('fecha_inicio'), 'fecha_fin': request.args.get('fecha_fin'), 'usuario': request.args.get('usuario'), 'area_grupo': request.args.get('area_grupo'), 'category': request.args.get('category'), 'severity': request.args.get('severity')}
    session['log_filtros'] = filtros
    query = db_session.query(ActivityLog, Usuario).outerjoin(Usuario, ActivityLog.username == Usuario.username)
    if filtros.get('fecha_inicio'): query = query.filter(ActivityLog.timestamp >= datetime.strptime(filtros['fecha_inicio'], '%Y-%m-%d'))
    if filtros.get('fecha_fin'): end_date = datetime.strptime(filtros['fecha_fin'], '%Y-%m-%d') + timedelta(days=1); query = query.filter(ActivityLog.timestamp < end_date)
    if filtros.get('usuario'): query = query.filter(ActivityLog.username.ilike(f"%{filtros['usuario']}%"))
    if filtros.get('area_grupo') and filtros.get('area_grupo') != 'Todos': query = query.filter(ActivityLog.area_grupo == filtros['area_grupo'])
    if filtros.get('category') and filtros.get('category') != 'Todos': query = query.filter(ActivityLog.category == filtros['category'])
    if filtros.get('severity') and filtros.get('severity') != 'Todos': query = query.filter(ActivityLog.severity == filtros['severity'])
    logs = query.order_by(ActivityLog.timestamp.desc()).limit(500).all()
    log_categories, log_severities = ['Autenticación', 'Datos', 'Seguridad', 'Sistema', 'General'], ['Info', 'Warning', 'Critical']
    return render_template('activity_log.html', logs=logs, filtros=filtros, log_categories=log_categories, log_severities=log_severities)

@app.route('/manage_roles', methods=['GET', 'POST'])
@login_required
@role_required(['ADMIN'])
@csrf_required
def manage_roles():
    if request.method == 'POST':
        nombre = request.form.get('nombre')
        if nombre:
            if not db_session.query(Rol).filter_by(nombre=nombre.upper()).first():
                db_session.add(Rol(nombre=nombre.upper())); db_session.commit()
                flash(f"Rol '{nombre.upper()}' creado exitosamente.", 'success')
            else: flash(f"El rol '{nombre.upper()}' ya existe.", 'danger')
    roles = db_session.query(Rol).order_by(Rol.nombre).all()
    return render_template('manage_roles.html', roles=roles)

@app.route('/delete_role/<int:role_id>', methods=['POST'])
@login_required
@role_required(['ADMIN'])
@csrf_required
def delete_role(role_id):
    rol = db_session.query(Rol).get(role_id)
    if rol:
        if rol.usuarios: flash(f"No se puede eliminar el rol '{rol.nombre}' porque tiene usuarios asignados.", 'danger')
        elif rol.nombre in ['ADMIN', 'IHP', 'FHP']: flash(f"No se puede eliminar el rol de sistema '{rol.nombre}'.", 'danger')
        else: flash(f"Rol '{rol.nombre}' eliminado.", 'success'); db_session.delete(rol); db_session.commit()
    else: flash("El rol no existe.", 'danger')
    return redirect(url_for('manage_roles'))

@app.route('/manage_turnos', methods=['GET', 'POST'])
@login_required
@role_required(['ADMIN'])
@csrf_required
def manage_turnos():
    if request.method == 'POST':
        nombre = request.form.get('nombre')
        if nombre:
            if not db_session.query(Turno).filter_by(nombre=nombre).first():
                db_session.add(Turno(nombre=nombre)); db_session.commit()
                flash(f"Turno '{nombre}' creado exitosamente.", 'success')
            else: flash(f"El turno '{nombre}' ya existe.", 'danger')
    turnos = db_session.query(Turno).order_by(Turno.nombre).all()
    return render_template('manage_turnos.html', turnos=turnos)

@app.route('/delete_turno/<int:turno_id>', methods=['POST'])
@login_required
@role_required(['ADMIN'])
@csrf_required
def delete_turno(turno_id):
    turno = db_session.query(Turno).get(turno_id)
    if turno:
        if turno.usuarios: flash(f"No se puede eliminar el turno '{turno.nombre}' porque tiene usuarios asignados.", 'danger')
        else: flash(f"Turno '{turno.nombre}' eliminado.", 'success'); db_session.delete(turno); db_session.commit()
    else: flash("El turno no existe.", 'danger')
    return redirect(url_for('manage_turnos'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=False if os.getenv('RENDER') else True)