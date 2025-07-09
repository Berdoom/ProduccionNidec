// Variable global para almacenar el estado inicial de la página al cargarla.
let initialTurnState = {};

document.addEventListener('DOMContentLoaded', () => {
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

    // --- Pre-cálculo del estado inicial ---
    const areas = Object.keys(PRONOSTICOS_DATA_JS);
    areas.forEach(areaName => {
        const areaSlug = toSlug(areaName);
        initialTurnState[areaSlug] = {};
        const turnos = Object.keys(PRONOSTICOS_DATA_JS[areaName] || {});

        turnos.forEach(turnoName => {
            const turnoData = PRONOSTICOS_DATA_JS[areaName][turnoName];
            const pronostico = parseInt(turnoData.pronostico, 10) || 0;
            let produccionTotal = 0;
            
            if (HORAS_TURNO_JS[turnoName]) {
                HORAS_TURNO_JS[turnoName].forEach(hora => {
                    if (turnoData[hora]) {
                        produccionTotal += parseInt(turnoData[hora], 10) || 0;
                    }
                });
            }

            initialTurnState[areaSlug][toSlug(turnoName)] = {
                pronostico: pronostico,
                produccion: produccionTotal,
                hasReason: !!turnoData.razon_desviacion
            };
        });
    });

    // --- Calcular todos los totales al cargar la página ---
    document.querySelectorAll('tr[data-area-slug], div.card').forEach(el => {
        const areaSlug = el.dataset.areaSlug || toSlug(el.querySelector('button[data-target^="#collapse"]')?.textContent.trim());
        if (areaSlug) {
            calculateAllTotals(areaSlug);
        }
    });
});

/**
 * Convierte un texto a un formato 'slug'
 * @param {string} text - El texto a convertir.
 * @returns {string} El texto en formato slug.
 */
function toSlug(text) {
    if (typeof text !== 'string') return '';
    return text.replace(/ /g, '_').replace(/\./g, '').replace(/\//g, '');
}

/**
 * Recarga la página de captura con la fecha seleccionada.
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
 * Sincroniza los inputs de móvil con los de escritorio (que son los que se envían) y recalcula.
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
 * Calcula totales y gestiona la visibilidad del ícono de razón para escritorio y móvil.
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
        (HORAS_TURNO_JS[turnoName] || []).forEach(hora => {
            const produccionInput = document.querySelector(`input[name="produccion_${areaSlug}_${hora}"]`);
            if (produccionInput && produccionInput.value) {
                totalProduccionTurno += parseInt(produccionInput.value, 10) || 0;
            }
        });
        
        // Actualizar UI para ambas vistas (Desktop y Móvil)
        const totalTurnoSpans = document.querySelectorAll(`#total_produccion_turno_${areaSlug}_${turnoSlug}, #mobile_total_produccion_turno_${areaSlug}_${turnoSlug}`);
        totalTurnoSpans.forEach(span => span.innerText = totalProduccionTurno);

        totalProduccionArea += totalProduccionTurno;
        totalPronosticoArea += pronosticoValor;

        // --- Lógica para el ícono de razón ---
        const iconContainers = document.querySelectorAll(`#reason_icon_container_${areaSlug}_${turnoSlug}, #mobile_reason_icon_container_${areaSlug}_${turnoSlug}`);
        const initialState = initialTurnState[areaSlug]?.[turnoSlug];

        if (initialState) {
            iconContainers.forEach(container => {
                container.innerHTML = ''; // Limpiar
                container.classList.remove('reason-icon-active');

                if (initialState.hasReason) {
                    container.innerHTML = '✅';
                } else if (initialState.pronostico > 0 && initialState.produccion < initialState.pronostico) {
                    container.innerHTML = '<i class="fas fa-exclamation-triangle text-warning"></i>';
                    container.classList.add('reason-icon-active'); // Hacerlo clickable
                }
            });
        }
    });

    const totalPronosticoSpan = document.getElementById(`total_pronostico_area_${areaSlug}`);
    if (totalPronosticoSpan) {
        totalPronosticoSpan.innerText = totalPronosticoArea;
    }

    const totalProduccionSpan = document.getElementById(`total_produccion_area_${areaSlug}`);
    if (totalProduccionSpan) {
        totalProduccionSpan.innerText = totalProduccionArea;
    }
}

/**
 * Prepara el modal con los datos correctos.
 * @param {HTMLElement} container - El contenedor del ícono que fue clickeado.
 */
function setReasonModalData(container) {
    if (!container.classList.contains('reason-icon-active')) {
        event.stopPropagation();
        return;
    }
    // CORRECCIÓN: No intentar modificar elementos que no existen en el modal.
    document.getElementById('modalDate').value = container.dataset.date;
    document.getElementById('modalArea').value = container.dataset.areaName;
    document.getElementById('modalTurno').value = container.dataset.turnoName;
    document.getElementById('reasonText').value = '';
}

/**
 * Muestra un modal de feedback.
 * @param {string} title - Título del modal.
 * @param {string} message - Mensaje del modal.
 * @param {boolean} isSuccess - Si es un mensaje de éxito.
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
 * Envía la razón de desviación al servidor.
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

                const iconContainers = document.querySelectorAll(`#reason_icon_container_${areaSlug}_${turnoSlug}, #mobile_reason_icon_container_${areaSlug}_${turnoSlug}`);
                iconContainers.forEach(container => {
                    container.innerHTML = '✅';
                    container.classList.remove('reason-icon-active');
                });

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
