// static/js/programa_lm.js

function initializeLMTable(updateUrl, csrfToken) {
    const cells = document.querySelectorAll('.lm-table .editable-cell');
    let originalValue = '';

    cells.forEach(cell => {
        // Guardar el valor original al enfocar la celda
        cell.addEventListener('focus', () => {
            originalValue = cell.textContent.trim();
        });

        // Guardar el cambio al desenfocar (blur)
        cell.addEventListener('blur', (e) => {
            const newValue = e.target.textContent.trim();
            
            // Solo guardar si el valor realmente cambió
            if (newValue !== originalValue) {
                const ordenId = e.target.dataset.ordenId;
                const columnaId = e.target.dataset.columnaId;
                const field = e.target.dataset.field; // Para columnas fijas

                // Si no tiene columnaId, es una columna fija (wip, item, qty)
                // Esta funcionalidad requiere una ruta API adicional. Por ahora, nos enfocamos en las dinámicas.
                if (columnaId) {
                    saveCellData(updateUrl, csrfToken, ordenId, columnaId, newValue, e.target);
                } else {
                    console.log(`Guardado de columna fija (${field}) no implementado en esta versión.`);
                    // Aquí se llamaría a otra función de guardado para las columnas fijas
                }
            }
        });
    });
}

function saveCellData(url, token, ordenId, columnaId, valor, cellElement) {
    cellElement.classList.add('saving'); // Feedback visual

    fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': token // Si usas CSRF con header
        },
        body: JSON.stringify({
            csrf_token: token, // Si usas CSRF con campo de formulario
            orden_id: ordenId,
            columna_id: columnaId,
            valor: valor
        })
    })
    .then(response => {
        cellElement.classList.remove('saving');
        if (!response.ok) {
            // Si hay un error, el backend enviará un JSON con el mensaje
            return response.json().then(err => Promise.reject(err));
        }
        return response.json();
    })
    .then(data => {
        if (data.status === 'success') {
            cellElement.classList.add('saved-success');
            setTimeout(() => cellElement.classList.remove('saved-success'), 1500);
        } else {
            throw new Error(data.message);
        }
    })
    .catch(error => {
        console.error('Error al guardar:', error);
        cellElement.classList.add('saved-error');
        alert(`Error al guardar: ${error.message || 'Error de red'}`);
        setTimeout(() => cellElement.classList.remove('saved-error'), 2000);
        // Podríamos revertir el valor de la celda aquí si quisiéramos
    });
}```

**Acción:** Crea una nueva carpeta `templates/modals/`. Dentro de ella, crea los siguientes dos archivos para los pop-ups de administrador.

**Archivo: `templates/modals/lm_add_row_modal.html`**
```html
<div class="modal fade" id="addRowModal" tabindex="-1" aria-labelledby="addRowModalLabel" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <form action="{{ url_for('add_row_lm') }}" method="POST">
                <input type="hidden" name="csrf_token" value="{{ session.csrf_token }}">
                <div class="modal-header">
                    <h5 class="modal-title" id="addRowModalLabel">Añadir Nueva Orden</h5>
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">×</span></button>
                </div>
                <div class="modal-body">
                    <div class="form-group">
                        <label for="wip_order">WIP Order</label>
                        <input type="text" class="form-control" name="wip_order" required>
                    </div>
                    <div class="form-group">
                        <label for="item">Item</label>
                        <input type="text" class="form-control" name="item">
                    </div>
                    <div class="form-group">
                        <label for="qty">QTY</label>
                        <input type="number" class="form-control" name="qty" value="1" required>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-dismiss="modal">Cancelar</button>
                    <button type="submit" class="btn btn-primary">Guardar Orden</button>
                </div>
            </form>
        </div>
    </div>
</div>