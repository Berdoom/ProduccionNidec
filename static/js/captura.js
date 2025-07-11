// Variable global para almacenar el estado de las razones ya enviadas.
let initialTurnState = {};

document.addEventListener('DOMContentLoaded', () => {
    // --- Lógica para advertir sobre cambios no guardados ---
    let hasUnsavedChanges = false;
    const productionForm = document.getElementById('productionForm');

    if (productionForm) {
        // Cualquier entrada en el formulario marca que hay cambios sin guardar.
        productionForm.addEventListener('input', () => { hasUnsavedChanges = true; });
        // Al enviar el formulario, se resetea la bandera.
        productionForm.addEventListener('submit', () => { hasUnsavedChanges = false; });
    }

    // Muestra una advertencia al intentar salir de la página si hay cambios.
    window.addEventListener('beforeunload', (e) => {
        if (hasUnsavedChanges) {
            e.preventDefault();
            e.returnValue = '';
        }
    });

    // --- Pre-cálculo del estado inicial (para saber si ya existe una razón) ---
    const areas = Object.keys(PRONOSTICOS_DATA_JS);
    areas.forEach(areaName => {
        const areaSlug = toSlug(areaName);
        initialTurnState[areaSlug] = {};
        const turnos = Object.keys(PRONOSTICOS_DATA_JS[areaName] || {});

        turnos.forEach(turnoName => {
            const turnoData = PRONOSTICOS_DATA_JS[areaName][turnoName];
            initialTurnState[areaSlug][toSlug(turnoName)] = {
                hasReason: !!turnoData.razon_desviacion
            };
        });
    });

    // --- Calcular todos los totales y actualizar iconos al cargar la página ---
    document.querySelectorAll('tr[data-area-slug]').forEach(row => {
        const areaSlug = row.dataset.areaSlug;
        if (areaSlug) {
            calculateAllTotals(areaSlug);
        }
    });
    // También para la vista móvil
    document.querySelectorAll('#accordionCaptura .card').forEach(card => {
        const areaSlug = toSlug(card.querySelector('button').textContent.trim());
        if(areaSlug) {
            calculateAllTotals(areaSlug);
        }
    });
});

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
 * Recarga la página de captura con la fecha seleccionada del calendario.
 */
function handleDateChange() {
    const form = document.getElementById('productionForm');
    const group = form.dataset.group;
    const fecha = document.getElementById('fecha').value;
    if (group && fecha) {
        window.location.href = `/captura/${group.toLowerCase()}?fecha=${fecha}`;
    }
}

/**
 * Sincroniza los inputs de la vista móvil con los de escritorio y recalcula totales.
 * @param {string} type - 'pronostico' o 'produccion'.
 * @param {string} areaSlug - El slug del área.
 * @param {string} identifier - El slug del turno o la hora.
 * @param {string} value - El nuevo valor del input.
 */
function syncAndCalc(type, areaSlug, identifier, value) {
    let desktopInputName = (type === 'pronostico') ? `pronostico_${areaSlug}_${identifier}` : `produccion_${areaSlug}_${identifier}`;
    const desktopInput = document.querySelector(`input[name="${desktopInputName}"]`);
    if (desktopInput) {
        desktopInput.value = value;
        calculateAllTotals(areaSlug);
    }
}

/**
 * Calcula todos los totales para un área y gestiona la visibilidad del ícono de razón.
 * @param {string} areaSlug - El slug del área a calcular.
 */
function calculateAllTotals(areaSlug) {
    let totalPronosticoArea = 0;
    let totalProduccionArea = 0;

    NOMBRES_TURNOS_JS.forEach(turnoName => {
        const turnoSlug = toSlug(turnoName);
        
        const pronosticoTurnoInput = document.querySelector(`input[name="pronostico_${areaSlug}_${turnoSlug}"]`);
        const pronosticoValor = parseInt(pronosticoTurnoInput.value, 10) || 0;
        
        let totalProduccionTurno = 0;
        let allInputsFilled = true; // CAMBIO: Bandera para verificar si todos los inputs del turno están llenos.
        
        (HORAS_TURNO_JS[turnoName] || []).forEach(hora => {
            const produccionInput = document.querySelector(`input[name="produccion_${areaSlug}_${hora}"]`);
            if (produccionInput && produccionInput.value !== '') {
                totalProduccionTurno += parseInt(produccionInput.value, 10) || 0;
            } else {
                allInputsFilled = false; // Si un input está vacío, la bandera es falsa.
            }
        });
        
        // Actualizar UI para ambas vistas (Desktop y Móvil)
        const totalTurnoSpans = document.querySelectorAll(`#total_produccion_turno_${areaSlug}_${turnoSlug}, #mobile_total_produccion_turno_${areaSlug}_${turnoSlug}`);
        totalTurnoSpans.forEach(span => span.innerText = totalProduccionTurno);

        totalProduccionArea += totalProduccionTurno;
        totalPronosticoArea += pronosticoValor;

        // --- CAMBIO: Nueva lógica para mostrar el ícono de razón ---
        const iconContainers = document.querySelectorAll(`#reason_icon_container_${areaSlug}_${turnoSlug}, #mobile_reason_icon_container_${areaSlug}_${turnoSlug}`);
        const hasExistingReason = initialTurnState[areaSlug]?.[turnoSlug]?.hasReason || false;

        iconContainers.forEach(container => {
            container.innerHTML = ''; // Limpiar contenedor
            container.classList.remove('reason-icon-active');

            if (hasExistingReason) {
                // Si ya se envió una razón, mostrar ícono de éxito.
                container.innerHTML = '<i class="fas fa-check-circle text-success" title="Razón ya enviada"></i>';
            } else if (allInputsFilled && pronosticoValor > 0 && totalProduccionTurno < pronosticoValor) {
                // Mostrar ícono de advertencia SÓLO si todos los campos están llenos y no se cumple el pronóstico.
                container.innerHTML = '<i class="fas fa-exclamation-triangle text-warning" title="Falta justificación"></i>';
                container.classList.add('reason-icon-active'); // Hacerlo clickable
            }
        });
    });

    // Actualizar totales del área
    const totalPronosticoSpan = document.getElementById(`total_pronostico_area_${areaSlug}`);
    if (totalPronosticoSpan) totalPronosticoSpan.innerText = totalPronosticoArea;

    const totalProduccionSpan = document.getElementById(`total_produccion_area_${areaSlug}`);
    if (totalProduccionSpan) totalProduccionSpan.innerText = totalProduccionArea;
}

/**
 * Prepara el modal con los datos del turno/área correctos antes de mostrarlo.
 * @param {HTMLElement} container - El contenedor del ícono que fue clickeado.
 */
function setReasonModalData(container) {
    // Si el ícono no es clickable (no tiene la clase 'reason-icon-active'), no hacer nada.
    if (!container.classList.contains('reason-icon-active')) {
        event.stopPropagation();
        return;
    }
    document.getElementById('modalDate').value = container.dataset.date;
    document.getElementById('modalArea').value = container.dataset.areaName;
    document.getElementById('modalTurno').value = container.dataset.turnoName;
    document.getElementById('reasonText').value = ''; // Limpiar el textarea
}

/**
 * Muestra un modal de feedback (éxito o error).
 * @param {string} title - Título del modal.
 * @param {string} message - Mensaje del modal.
 * @param {boolean} isSuccess - Si es un mensaje de éxito para darle el color correspondiente.
 */
function showFeedback(title, message, isSuccess) {
    const header = document.getElementById('feedbackModalHeader');
    const modalLabel = document.getElementById('feedbackModalLabel');
    const modalBody = document.getElementById('feedbackModalBody');
    
    if (header && modalLabel && modalBody) {
        modalLabel.innerText = title;
        modalBody.innerText = message;
        header.className = isSuccess ? 'modal-header bg-success text-white' : 'modal-header bg-danger text-white';
        $('#feedbackModal').modal('show');
    }
}

/**
 * Envía la razón de desviación al servidor vía AJAX.
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
                showFeedback('Éxito', response.message, true);
                
                const areaSlug = toSlug(areaName);
                const turnoSlug = toSlug(turnoName);

                // Actualizar el ícono a 'éxito' y deshabilitarlo.
                const iconContainers = document.querySelectorAll(`#reason_icon_container_${areaSlug}_${turnoSlug}, #mobile_reason_icon_container_${areaSlug}_${turnoSlug}`);
                iconContainers.forEach(container => {
                    container.innerHTML = '<i class="fas fa-check-circle text-success" title="Razón ya enviada"></i>';
                    container.classList.remove('reason-icon-active');
                });

                // Actualizar el estado para que no vuelva a pedir la razón en esta sesión.
                if (initialTurnState[areaSlug] && initialTurnState[areaSlug][turnoSlug]) {
                    initialTurnState[areaSlug][turnoSlug].hasReason = true;
                }
                
            } else {
                showFeedback('Error al Guardar', response.message || 'Ocurrió un error desconocido.', false);
            }
        },
        error: function(jqXHR) {
            showFeedback('Error de Conexión', 'No se pudo comunicar con el servidor.', false);
        }
    });
}
