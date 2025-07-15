// Variable global para la instancia de SortableJS
let sortableInstance = null;

// ===================================================================
// === CONFIGURACIÓN DE LA PALETA DE COLORES ESTILO EXCEL ===
// ===================================================================
const EXCEL_PALETTE = {
    theme: [
        ['#FFFFFF', '#F2F2F2', '#D9D9D9', '#BFBFBF', '#A6A6A6', '#808080'],
        ['#000000', '#0D0D0D', '#262626', '#404040', '#595959', '#737373'],
        ['#BF9000', '#FFC000', '#FFD966', '#FFF2CC', '#FBE5D6', '#E6B9B8'],
        ['#0070C0', '#00B0F0', '#9DC3E6', '#BDD7EE', '#DEEAF6', '#DAE3F3'],
        ['#00B050', '#92D050', '#A9D18E', '#C6E0B4', '#E2EFDA', '#D9EAD3'],
        ['#7030A0', '#C000C0', '#DFA6E4', '#E6B8E8', '#F2DCDB', '#EAD1DC']
    ],
    standard: [
        '#C00000', '#FF0000', '#FFC000', '#FFFF00',
        '#92D050', '#00B050', '#00B0F0', '#0070C0',
        '#002060', '#7030A0'
    ]
};

/**
 * Crea el HTML para una paleta de colores.
 * @returns {string} El HTML de la paleta.
 */
function createColorPaletteHTML() {
    let html = '<div class="context-menu-section-title">Colores del tema</div>';
    html += '<div class="theme-colors-container">';
    EXCEL_PALETTE.theme.forEach(column => {
        html += '<div class="color-column">';
        column.forEach(color => {
            // --- CAMBIO AQUÍ: Usamos una variable CSS --bg-color ---
            html += `<div class="color-box" style="--bg-color:${color};" data-color="${color}"></div>`;
        });
        html += '</div>';
    });
    html += '</div>';

    html += '<div class="context-menu-section-title">Colores estándar</div>';
    html += '<div class="color-palette">';
    EXCEL_PALETTE.standard.forEach(color => {
        // --- CAMBIO AQUÍ: Usamos una variable CSS --bg-color ---
        html += `<div class="color-box" style="--bg-color:${color};" data-color="${color}"></div>`;
    });
    html += '</div>';
    return html;
}

/**
 * Inicializa la lógica para las celdas editables.
 */
function initializeEditableCells(updateUrl, csrfToken) {
    document.querySelectorAll('.lm-table .editable-cell').forEach(cell => {
        let originalValue = cell.textContent.trim();
        cell.addEventListener('focus', () => { originalValue = cell.textContent.trim(); });
        cell.addEventListener('blur', (e) => {
            const newValue = e.target.textContent.trim();
            if (newValue !== originalValue) {
                saveCellData(updateUrl, csrfToken, e.target.dataset.ordenId, e.target.dataset.columnaId, { valor: newValue });
            }
        });
    });
}

/**
 * Inicializa el menú contextual avanzado.
 */
function initializeContextMenu(updateUrl, csrfToken) {
    const contextMenu = document.getElementById('cell-context-menu');
    const bgPaletteContainer = document.getElementById('bg-palette-content');
    const textPaletteContainer = document.getElementById('text-palette-content');
    const nativeColorPicker = document.getElementById('native-color-picker');
    let activeCell = null;
    let activeProperty = 'backgroundColor';

    // Generar las paletas y añadirlas al DOM
    const paletteHTML = createColorPaletteHTML();
    bgPaletteContainer.innerHTML = paletteHTML;
    textPaletteContainer.innerHTML = paletteHTML;

    // Manejo de pestañas (Fondo / Fuente)
    document.querySelectorAll('.context-menu-tab').forEach(tab => {
        tab.addEventListener('click', (e) => {
            document.querySelectorAll('.context-menu-tab, .context-menu-palette-content').forEach(el => el.classList.remove('active'));
            e.target.classList.add('active');
            const targetContent = document.getElementById(e.target.dataset.target);
            targetContent.classList.add('active');
            activeProperty = e.target.dataset.target.startsWith('bg') ? 'backgroundColor' : 'color';
        });
    });

    // Abrir el menú contextual
    document.querySelectorAll('.lm-table .editable-cell').forEach(cell => {
        cell.addEventListener('contextmenu', e => {
            e.preventDefault();
            activeCell = e.target;
            contextMenu.style.top = `${e.pageY}px`;
            contextMenu.style.left = `${e.pageX}px`;
            contextMenu.style.display = 'block';
        });
    });

    // Cerrar menú
    document.addEventListener('click', () => { if (contextMenu.style.display === 'block') contextMenu.style.display = 'none'; });
    contextMenu.addEventListener('click', e => e.stopPropagation());

    // Listener unificado para todos los clics en colores
    contextMenu.addEventListener('click', (e) => {
        if (e.target.classList.contains('color-box')) {
            if (!activeCell) return;
            const color = e.target.dataset.color;
            activeCell.style[activeProperty] = color;
            saveCurrentStyles();
            contextMenu.style.display = 'none';
        }
    });
    
    // Lógica para el botón "Más Colores"
    document.getElementById('more-colors-btn').addEventListener('click', () => {
        nativeColorPicker.click();
    });

    // --- CORRECCIÓN CLAVE AQUÍ ---
    // Cambiamos 'input' por 'change' para que solo se guarde al finalizar la selección.
    nativeColorPicker.addEventListener('change', () => {
        if (!activeCell) return;
        activeCell.style[activeProperty] = nativeColorPicker.value;
        saveCurrentStyles();
    });

    // Lógica para el botón de resetear estilos
    document.getElementById('reset-style-btn').addEventListener('click', () => {
        if (!activeCell) return;
        activeCell.style.backgroundColor = '';
        activeCell.style.color = '';
        saveCurrentStyles();
        contextMenu.style.display = 'none';
    });

    // Función auxiliar para guardar los estilos de la celda activa
    function saveCurrentStyles() {
        if (!activeCell) return;
        saveCellData(updateUrl, csrfToken, activeCell.dataset.ordenId, activeCell.dataset.columnaId, {
            estilos_css: {
                backgroundColor: activeCell.style.backgroundColor,
                color: activeCell.style.color
            }
        });
    }
}

/**
 * Activa o desactiva el modo de reordenamiento de columnas.
 */
function toggleReorderMode(button, reorderUrl, csrfToken) {
    const tableHeaderRow = document.getElementById('lm-table-header-row');
    const headers = tableHeaderRow.querySelectorAll('th[data-columna-id]');

    if (sortableInstance) {
        const orderedIds = sortableInstance.toArray();
        fetch(reorderUrl, {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ ordered_ids: orderedIds, csrf_token: csrfToken })
        }).then(res => res.json()).then(data => {
            if (data.status === 'success') {
                alert('¡Orden guardado! La página se recargará.');
                window.location.reload();
            } else { alert('Error al guardar: ' + data.message); }
        });
        sortableInstance.destroy(); sortableInstance = null;
        headers.forEach(th => th.classList.remove('sortable-handle'));
        button.innerHTML = '<i class="fas fa-sort mr-1"></i> Ordenar Columnas';
        button.classList.remove('btn-success');
    } else {
        sortableInstance = new Sortable(tableHeaderRow, {
            animation: 150, ghostClass: 'sortable-ghost', draggable: 'th[data-columna-id]',
        });
        headers.forEach(th => th.classList.add('sortable-handle'));
        button.innerHTML = '<i class="fas fa-save mr-1"></i> Guardar Orden';
        button.classList.add('btn-success');
    }
}

/**
 * Función genérica para guardar datos de la celda (valor y/o estilos).
 */
function saveCellData(url, token, ordenId, columnaId, payload) {
    payload.csrf_token = token; payload.orden_id = ordenId; payload.columna_id = columnaId;
    fetch(url, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
    })
    .then(response => {
        if (!response.ok) return response.json().then(err => Promise.reject(err));
        return response.json();
    })
    .then(data => console.log('Guardado exitoso:', data.message))
    .catch(error => {
        console.error('Error al guardar:', error);
        alert(`Error al guardar: ${error.message || 'Error de red'}`);
    });
}