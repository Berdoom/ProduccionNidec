// Variable global para almacenar el estado de las razones ya enviadas.
let PRONOSTICOS_DATA;
let HORAS_TURNO;
let NOMBRES_TURNOS;

/**
 * Inicializa la página de captura, configurando los listeners y calculando los totales iniciales.
 * @param {object} horasTurnoData - Datos de las horas por turno desde el backend.
 * @param {Array<string>} nombresTurnosData - Nombres de los turnos.
 * @param {object} pronosticosData - Datos de pronósticos existentes.
 */
function initializeCapturaPage(horasTurnoData, nombresTurnosData, pronosticosData) {
    HORAS_TURNO = horasTurnoData;
    NOMBRES_TURNOS = nombresTurnosData;
    PRONOSTICOS_DATA = pronosticosData;

    // --- Lógica para advertir sobre cambios no guardados ---
    let hasUnsavedChanges = false;
    const productionForm = document.getElementById('productionForm');

    if (productionForm) {
        productionForm.addEventListener('input', () => { hasUnsavedChanges = true; });
        productionForm.addEventListener('submit', () => { hasUnsavedChanges = false; });
    }

    window.addEventListener('beforeunload', (e) => {
        if (hasUnsavedChanges) {
            e.preventDefault();
            e.returnValue = '';
        }
    });

    // --- Calcular todos los totales y actualizar iconos al cargar la página ---
    document.querySelectorAll('[data-area-slug]').forEach(el => {
        if (el.dataset.areaSlug) {
            calculateAllTotalsForArea(el.dataset.areaSlug);
        }
    });
    document.querySelectorAll('input.adaptive-font').forEach(updateInputFontSize);
}

/**
 * Convierte un texto a un formato 'slug' (ej: "Turno A" -> "Turno_A").
 * @param {string} text - El texto a convertir.
 * @returns {string} El texto en formato slug.
 */
function toSlug(text) {
    if (typeof text !== 'string') return '';
    return text.replace(/ /g, '_').replace(/\./g, '').replace(/\//g, '');
}

/**
 * Ajusta el tamaño de la fuente de un input basado en la longitud de su contenido.
 * @param {HTMLInputElement} input - El campo de entrada.
 */
function updateInputFontSize(input) {
    const len = input.value.length;
    input.classList.remove('input-font-sm', 'input-font-xs');
    if (len >= 5) {
        input.classList.add('input-font-xs');
    } else if (len === 4) {
        input.classList.add('input-font-sm');
    }
}

/**
 * Se activa cuando un valor de entrada cambia. Sincroniza los valores entre las vistas
 * de escritorio y móvil y recalcula los totales para el área afectada.
 * @param {HTMLInputElement} inputElement - El campo de entrada que cambió.
 */
function onInputChanged(inputElement) {
    const name = inputElement.name;
    const value = inputElement.value;

    // Sincronizar valor con todos los campos que tengan el mismo nombre.
    document.querySelectorAll(`input[name="${name}"]`).forEach(counterpart => {
        if (counterpart !== inputElement) {
            counterpart.value = value;
        }
    });

    // Adaptar tamaño de fuente.
    updateInputFontSize(inputElement);

    // Encontrar el slug del área y recalcular todo para esa fila/sección.
    const areaSlug = inputElement.closest('[data-area-slug]')?.dataset.areaSlug;
    if (areaSlug) {
        calculateAllTotalsForArea(areaSlug);
    }
}

/**
 * Calcula todos los totales para un área específica, actualiza la UI y aplica los
 * estilos de color basados en el rendimiento.
 * @param {string} areaSlug - El slug del área a calcular.
 */
function calculateAllTotalsForArea(areaSlug) {
    const areaContainer = document.querySelector(`[data-area-slug="${areaSlug}"]`);
    if (!areaContainer) return;

    const areaName = areaContainer.dataset.areaName;
    let totalPronosticoArea = 0;
    let totalProduccionArea = 0;

    NOMBRES_TURNOS.forEach(turnoName => {
        const turnoSlug = toSlug(turnoName);
        const pronosticoInput = document.querySelector(`input[name="pronostico_${areaSlug}_${turnoSlug}"]`);
        const pronosticoValor = Number(pronosticoInput.value) || 0;

        let totalProduccionTurno = 0;
        const horasDelTurno = HORAS_TURNO[turnoName] || [];
        const hourlyTarget = pronosticoValor > 0 && horasDelTurno.length > 0 ? pronosticoValor / horasDelTurno.length : 0;

        // Calcular producción por hora y colorear inputs
        horasDelTurno.forEach(hora => {
            const produccionInputs = document.querySelectorAll(`input[name="produccion_${areaSlug}_${hora}"]`);
            const valorProduccion = Number(produccionInputs[0].value) || 0;
            
            produccionInputs.forEach(input => {
                input.classList.remove('input-success', 'input-warning');
                if (hourlyTarget > 0 && input.value !== '') {
                    if (valorProduccion >= hourlyTarget) {
                        input.classList.add('input-success');
                    } else {
                        input.classList.add('input-warning');
                    }
                }
            });
            totalProduccionTurno += valorProduccion;
        });
        
        // Actualizar el total del turno en la UI
        document.querySelectorAll(`#total_produccion_turno_${areaSlug}_${turnoSlug}, #mobile_total_produccion_turno_${areaSlug}_${turnoSlug}`)
            .forEach(span => span.textContent = totalProduccionTurno.toLocaleString());

        totalProduccionArea += totalProduccionTurno;
        totalPronosticoArea += pronosticoValor;

        // Colorear la celda del total del turno
        updateTurnoTotalCellColor(areaSlug, turnoSlug, totalProduccionTurno, pronosticoValor);
        
        // Actualizar el ícono de validación/razón
        updateValidationIcon(areaSlug, turnoSlug, areaName, turnoName, totalProduccionTurno, pronosticoValor);
    });
    
    // Actualizar totales del área en la UI
    const totalPronosticoEl = document.getElementById(`total_pronostico_area_${areaSlug}`);
    if(totalPronosticoEl) totalPronosticoEl.textContent = totalPronosticoArea.toLocaleString();
    
    const totalProduccionEl = document.getElementById(`total_produccion_area_${areaSlug}`);
    if(totalProduccionEl) totalProduccionEl.textContent = totalProduccionArea.toLocaleString();
}

/**
 * Aplica la clase de color correcta a la celda del total del turno.
 * @param {string} areaSlug 
 * @param {string} turnoSlug 
 * @param {number} totalProduccion 
 * @param {number} pronostico 
 */
function updateTurnoTotalCellColor(areaSlug, turnoSlug, totalProduccion, pronostico) {
    const eficiencia = pronostico > 0 ? (totalProduccion / pronostico) * 100 : 0;
    const totalTurnoSpans = document.querySelectorAll(`#total_produccion_turno_${areaSlug}_${turnoSlug}, #mobile_total_produccion_turno_${areaSlug}_${turnoSlug}`);
    
    totalTurnoSpans.forEach(span => {
        const cell = span.closest('td, .turno-total-mobile');
        if (!cell) return;
        
        cell.classList.remove('total-cell-success', 'total-cell-warning', 'total-cell-danger');

        if (pronostico > 0) {
            if (eficiencia >= 95) {
                cell.classList.add('total-cell-success');
            } else if (eficiencia >= 80) {
                cell.classList.add('total-cell-warning');
            } else {
                cell.classList.add('total-cell-danger');
            }
        }
    });
}

/**
 * Actualiza el ícono de validación (check o advertencia) para un turno.
 * @param {string} areaSlug 
 * @param {string} turnoSlug 
 * @param {string} areaName 
 * @param {string} turnoName 
 * @param {number} totalProduccion 
 * @param {number} pronostico 
 */
function updateValidationIcon(areaSlug, turnoSlug, areaName, turnoName, totalProduccion, pronostico) {
    const hasExistingReason = PRONOSTICOS_DATA[areaName]?.[turnoName]?.razon_desviacion;
    let allInputsFilled = true;
    (HORAS_TURNO[turnoName] || []).forEach(hora => {
        const input = document.querySelector(`input[name="produccion_${areaSlug}_${hora}"]`);
        if (!input || input.value === '') {
            allInputsFilled = false;
        }
    });

    document.querySelectorAll(`#validation_icon_container_${areaSlug}_${turnoSlug}, #mobile_validation_icon_container_${areaSlug}_${turnoSlug}`)
        .forEach(container => {
            if (container) {
                container.innerHTML = '';
                container.classList.remove('clickable-icon');
                container.style.cursor = 'default';

                if (hasExistingReason) {
                    container.innerHTML = '<i class="fas fa-check-circle text-success" title="Razón ya enviada"></i>';
                } else if (allInputsFilled && pronostico > 0 && totalProduccion < pronostico) {
                    container.innerHTML = '<i class="fas fa-exclamation-triangle text-warning" title="Justificar desviación"></i>';
                    container.classList.add('clickable-icon');
                    container.style.cursor = 'pointer';
                }
            }
        });
}

/**
 * Maneja el clic en el ícono de validación, abriendo el modal si es necesario.
 * @param {HTMLElement} container - El contenedor del ícono que fue clickeado.
 */
function handleValidationIconClick(container) {
    if (container.classList.contains('clickable-icon')) {
        document.getElementById('modalDate').value = container.dataset.date;
        document.getElementById('modalArea').value = container.dataset.areaName;
        document.getElementById('modalTurno').value = container.dataset.turnoName;
        document.getElementById('reasonText').value = '';
        $('#reasonModal').modal('show');
    }
}

/**
 * Envía la razón de desviación al servidor a través de AJAX.
 */
function submitReason() {
    const reasonText = document.getElementById('reasonText').value;
    if (!reasonText.trim()) {
        alert('La razón no puede estar vacía.');
        return;
    }

    $('#reasonModal').modal('hide');
    
    const form = document.getElementById('productionForm');
    const submitUrl = form.dataset.submitReasonUrl;
    const csrfToken = document.querySelector('input[name="csrf_token"]').value;
    const group = form.dataset.group;

    const areaName = document.getElementById('modalArea').value;
    const turnoName = document.getElementById('modalTurno').value;
    const areaSlug = toSlug(areaName);

    $.ajax({
        url: submitUrl,
        type: "POST",
        data: {
            csrf_token: csrfToken,
            date: document.getElementById('modalDate').value,
            area: areaName,
            group: group,
            reason: reasonText,
            turno_name: turnoName
        },
        success: function(response) {
            if (response.status === 'success') {
                if (PRONOSTICOS_DATA[areaName] && PRONOSTICOS_DATA[areaName][turnoName]) {
                    PRONOSTICOS_DATA[areaName][turnoName].razon_desviacion = reasonText;
                }
                calculateAllTotalsForArea(areaSlug);
                alert(response.message);
            } else {
                alert('Error: ' + response.message);
            }
        },
        error: function() {
            alert('No se pudo comunicar con el servidor.');
        }
    });
}
