document.addEventListener('DOMContentLoaded', function() {
    // Inicializar todas las funcionalidades de la página
    initializeActionsToggle();
    
    const csrfToken = document.querySelector('input[name="csrf_token"]')?.value;
    if (!csrfToken) {
        console.error("CSRF Token no encontrado. Las funciones de guardado estarán deshabilitadas.");
        return;
    }

    const updateCellUrl = '/programa_lm/update_cell';
    const reorderUrl = '/programa_lm/reorder_columns';

    // Se inicializan las mismas funciones para escritorio y móvil
    initializeEditableCells(updateCellUrl, csrfToken);
    initializeContextMenu(updateCellUrl, csrfToken);
    initializeAdminControls(reorderUrl, csrfToken);
});

/**
 * Lógica para el botón de ocultar/mostrar la columna de acciones.
 */
function initializeActionsToggle() {
    const toggleBtn = document.getElementById('toggleActionsBtn');
    const table = document.querySelector('.lm-table');

    if (!toggleBtn || !table) return;

    const isHidden = localStorage.getItem('actionsColumnHidden') === 'true';
    if (isHidden) {
        table.classList.add('actions-hidden');
        toggleBtn.innerHTML = '<i class="fas fa-eye"></i> Mostrar Acciones';
    }

    toggleBtn.addEventListener('click', () => {
        table.classList.toggle('actions-hidden');
        const currentlyHidden = table.classList.contains('actions-hidden');
        toggleBtn.innerHTML = currentlyHidden ? '<i class="fas fa-eye"></i> Mostrar Acciones' : '<i class="fas fa-eye-slash"></i> Ocultar Acciones';
        localStorage.setItem('actionsColumnHidden', currentlyHidden ? 'true' : 'false');
    });
}

/**
 * Guarda los datos de una celda en el servidor.
 */
function saveCellData(url, token, cell, payload) {
    cell.classList.remove('saved-success', 'saved-error');
    if (!cell.classList.contains('mobile-editable-cell')) {
        cell.classList.add('saving');
    }
    const body = { csrf_token: token, orden_id: cell.dataset.ordenId, columna_id: cell.dataset.columnaId, ...payload };
    fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
    .then(response => { if (!response.ok) return response.json().then(err => Promise.reject(err)); return response.json(); })
    .then(data => { 
        if (data.status === 'success' && !cell.classList.contains('mobile-editable-cell')) {
            cell.classList.add('saved-success');
            setTimeout(() => cell.classList.remove('saved-success'), 1500);
        }
    })
    .catch(error => { 
        console.error('Error al guardar:', error); 
        cell.classList.add('saved-error'); 
        alert(`Error al guardar: ${error.message || 'Error de red'}`); 
    })
    .finally(() => { 
        if (!cell.classList.contains('mobile-editable-cell')) {
            cell.classList.remove('saving');
        }
    });
}

/**
 * Inicializa la edición en línea para las celdas de la tabla de escritorio.
 */
function initializeEditableCells(url, token) {
    document.querySelectorAll('.lm-table .editable-cell').forEach(cell => {
        let originalValue = cell.textContent.trim();
        cell.addEventListener('focus', () => { originalValue = cell.textContent.trim(); });
        cell.addEventListener('blur', (e) => {
            const newValue = e.target.textContent.trim();
            if (newValue !== originalValue) {
                saveCellData(url, token, e.target, { valor: newValue });
            }
        });
    });
}

/**
 * INICIALIZA EL MENÚ CONTEXTUAL UNIFICADO (CLIC DERECHO O PULSACIÓN LARGA)
 */
function initializeContextMenu(url, token) {
    const contextMenu = document.getElementById('cell-context-menu');
    if (!contextMenu) return;

    let activeCellElement = null; // El elemento a estilizar (<td> o <p>)
    let activeContainer = null;   // El contenedor con data-attributes (<td> o <div>)
    
    // Por defecto, la propiedad a cambiar es el fondo (para la pestaña "Simple")
    let activeProperty = 'backgroundColor';

    // --- GENERACIÓN DE PALETAS ---
    const simpleColors = ['#00B050', '#FFFF00', '#FF0000'];
    const themeColors = [
        ['#FFFFFF', '#000000', '#EEECE1', '#1F497D', '#4F81BD', '#C0504D', '#9BBB59', '#8064A2', '#4BACC6', '#F79646'],
        ['#F2F2F2', '#7F7F7F', '#DDD9C3', '#C6D9F0', '#DCE6F1', '#F2DCDB', '#EBF1DE', '#E5E0EC', '#DBEEF3', '#FDEADA'],
        ['#D8D8D8', '#595959', '#C4BD97', '#8DB3E2', '#B8CCE4', '#E5B9B7', '#D7E3BC', '#CCC1D9', '#B7DDE8', '#FBD5B5'],
        ['#BFBFBF', '#3F3F3F', '#938953', '#548DD4', '#95B3D7', '#D99694', '#C3D69B', '#B2A2C7', '#92CDDC', '#FAC08F'],
        ['#A5A5A5', '#262626', '#494429', '#17365D', '#366092', '#953734', '#76923C', '#5F497A', '#31859B', '#E36C09'],
        ['#7F7F7F', '#0C0C0C', '#1D1B10', '#0F243E', '#244061', '#632423', '#4F6128', '#3F3151', '#205867', '#974806']
    ];
    const standardColors = ['#C00000', '#FF0000', '#FFC000', '#FFFF00', '#92D050', '#00B050', '#00B0F0', '#0070C0', '#002060', '#7030A0'];

    function createFullPaletteHTML(colors, isTheme) {
        let html = `<div class="${isTheme ? 'theme-colors-container' : 'standard-colors-container'}">`;
        if (isTheme) {
            for (let col = 0; col < colors[0].length; col++) {
                html += '<div class="color-column">';
                for (let row = 0; row < colors.length; row++) {
                    html += `<div class="color-box" data-color="${colors[row][col]}" style="--bg-color: ${colors[row][col]}"></div>`;
                }
                html += '</div>';
            }
        } else {
            colors.forEach(color => {
                html += `<div class="color-box" data-color="${color}" style="--bg-color: ${color}"></div>`;
            });
        }
        html += '</div>';
        return html;
    }
    
    function populateAllPalettes() {
        const simplePaletteContainer = document.getElementById('simple-palette-content');
        if (simplePaletteContainer && !simplePaletteContainer.innerHTML.trim()) {
            let simpleHTML = '<div class="simple-palette-grid">';
            simpleColors.forEach(color => {
                simpleHTML += `<div class="color-box" data-color="${color}" style="background-color: ${color};"></div>`;
            });
            simpleHTML += '</div>';
            simplePaletteContainer.innerHTML = simpleHTML;
        }

        const bgPaletteContainer = document.getElementById('bg-palette-content');
        if (bgPaletteContainer && !bgPaletteContainer.innerHTML.trim()) {
            bgPaletteContainer.innerHTML = `<div class="context-menu-section-title">Colores del Tema</div>${createFullPaletteHTML(themeColors, true)}<div class="context-menu-section-title">Colores Estándar</div>${createFullPaletteHTML(standardColors, false)}`;
        }

        const fontPaletteContainer = document.getElementById('font-palette-content');
        if (fontPaletteContainer && !fontPaletteContainer.innerHTML.trim()) {
            fontPaletteContainer.innerHTML = `<div class="context-menu-section-title">Colores del Tema</div>${createFullPaletteHTML(themeColors, true)}<div class="context-menu-section-title">Colores Estándar</div>${createFullPaletteHTML(standardColors, false)}`;
        }
    }
    
    populateAllPalettes();

    // --- MANEJO DE EVENTOS ---
    contextMenu.querySelectorAll('.context-menu-tab').forEach(tab => {
        tab.addEventListener('click', (e) => {
            contextMenu.querySelectorAll('.context-menu-tab, .context-menu-palette-content').forEach(el => el.classList.remove('active'));
            const targetContent = document.getElementById(e.target.dataset.target);
            e.target.classList.add('active');
            if (targetContent) targetContent.classList.add('active');
            
            activeProperty = (e.target.dataset.target === 'font-palette-content') ? 'color' : 'backgroundColor';
        });
    });
    
    const allEditableCells = document.querySelectorAll('.editable-cell, .mobile-editable-cell');
    allEditableCells.forEach(cell => {
        cell.addEventListener('contextmenu', e => {
            e.preventDefault();
            
            activeContainer = e.currentTarget;
            activeCellElement = activeContainer.classList.contains('mobile-editable-cell') ? activeContainer.querySelector('p') : activeContainer;
            
            const { clientX, clientY } = (e.touches && e.touches[0]) ? e.touches[0] : e;
            const menuWidth = contextMenu.offsetWidth;
            const menuHeight = contextMenu.offsetHeight;
            
            let leftPosition = clientX + 5 > window.innerWidth - menuWidth ? clientX - menuWidth - 5 : clientX + 5;
            let topPosition = clientY + 5 > window.innerHeight - menuHeight ? clientY - menuHeight - 5 : clientY + 5;
            
            contextMenu.style.left = `${leftPosition}px`;
            contextMenu.style.top = `${topPosition}px`;
            contextMenu.style.display = 'block';

            const boldCheckbox = document.getElementById('bold-checkbox');
            if (boldCheckbox) boldCheckbox.checked = getComputedStyle(activeCellElement).fontWeight >= 700;
        });
    });

    document.addEventListener('click', () => { if (contextMenu.style.display === 'block') contextMenu.style.display = 'none'; });
    contextMenu.addEventListener('click', e => e.stopPropagation());

    contextMenu.addEventListener('click', (e) => {
        if (!activeCellElement) return;
        const target = e.target;
        
        const colorBox = target.closest('.color-box');
        if (colorBox) {
            if (activeProperty === 'backgroundColor') {
                activeContainer.style.backgroundColor = colorBox.dataset.color;
            } else {
                activeCellElement.style.color = colorBox.dataset.color;
            }
            saveCurrentStyles();
        } else if (target.closest('#format-bold')) {
            const checkbox = document.getElementById('bold-checkbox');
            if (e.target !== checkbox) checkbox.checked = !checkbox.checked;
            activeCellElement.style.fontWeight = checkbox.checked ? 'bold' : '';
            saveCurrentStyles();
        } else if (target.closest('#reset-style-btn')) {
            activeContainer.style.backgroundColor = '';
            activeCellElement.style.color = '';
            activeCellElement.style.fontWeight = '';
            saveCurrentStyles();
        }
    });

    function saveCurrentStyles() {
        if (!activeContainer) return;
        saveCellData(url, token, activeContainer, {
            estilos_css: {
                backgroundColor: activeContainer.style.backgroundColor,
                color: activeCellElement.style.color,
                fontWeight: activeCellElement.style.fontWeight,
            }
        });
    }
}

/**
 * Inicializa los controles de administrador (Reordenar columnas).
 */
function initializeAdminControls(reorderUrl, token) {
    const reorderBtn = document.getElementById('reorderBtn');
    const headerRow = document.getElementById('lm-table-header-row');
    if (!reorderBtn || !headerRow) return;
    
    let sortableInstance = null;
    reorderBtn.addEventListener('click', function() {
        if (sortableInstance) {
            const orderedIds = sortableInstance.toArray();
            fetch(reorderUrl, {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ ordered_ids: orderedIds.filter(id => id), csrf_token: token })
            })
            .then(res => res.ok ? res.json() : Promise.reject(new Error('Error en la respuesta del servidor.')))
            .then(data => {
                if (data.status === 'success') {
                    alert('¡Orden guardado! La página se recargará.');
                    window.location.reload();
                } else { throw new Error(data.message); }
            })
            .catch(error => alert('Error al guardar: ' + error.message));

            sortableInstance.destroy(); 
            sortableInstance = null;
            headerRow.querySelectorAll('th.sortable-handle').forEach(th => th.classList.remove('sortable-handle'));
            this.innerHTML = '<i class="fas fa-sort mr-1"></i> Ordenar';
            this.classList.replace('btn-success', 'btn-info');
        } else {
            sortableInstance = new Sortable(headerRow, {
                animation: 150, 
                ghostClass: 'sortable-ghost',
                filter: '.non-draggable',
                dataIdAttr: 'data-col-id',
            });
            headerRow.querySelectorAll('th[data-col-id]:not(.non-draggable)').forEach(th => th.classList.add('sortable-handle'));
            this.innerHTML = '<i class="fas fa-save mr-1"></i> Guardar Orden';
            this.classList.replace('btn-info', 'btn-success');
        }
    });
}