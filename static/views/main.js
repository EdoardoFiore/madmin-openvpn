/**
 * OpenVPN Module - Frontend
 * 
 * Main view for OpenVPN management:
 * - Instances list and CRUD
 * - Clients management with certificate status
 * - PKI management (certificate renewal)
 * - Firewall groups
 */

const MODULE_BASE = '/api/modules/openvpn';

// Global state
let currentInstance = null;
let networkInterfaces = [];

/**
 * Initialize the OpenVPN module view
 */
async function init() {
    renderMainView();
    await loadInstances();
    setupEventListeners();
}

/**
 * Render the main container
 */
function renderMainView() {
    const container = document.getElementById('module-content');
    container.innerHTML = `
        <div class="page-header d-print-none mb-4">
            <div class="row align-items-center">
                <div class="col-auto">
                    <h2 class="page-title">
                        <i class="ti ti-lock me-2"></i>
                        OpenVPN Manager
                    </h2>
                </div>
                <div class="col-auto ms-auto">
                    <button class="btn btn-primary" id="btn-create-instance">
                        <i class="ti ti-plus me-2"></i>Nuova Istanza
                    </button>
                </div>
            </div>
        </div>
        
        <div id="instances-container">
            <div class="text-center py-5">
                <div class="spinner-border text-primary"></div>
                <p class="text-muted mt-2">Caricamento istanze...</p>
            </div>
        </div>
        
        <!-- Instance Detail Modal -->
        <div class="modal modal-blur fade" id="modal-instance-detail" tabindex="-1">
            <div class="modal-dialog modal-xl">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="modal-instance-title">Dettaglio Istanza</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body" id="modal-instance-body">
                        <!-- Instance details are rendered here -->
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Create Instance Modal -->
        <div class="modal modal-blur fade" id="modal-create-instance" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Crea Nuova Istanza OpenVPN</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <form id="form-create-instance">
                            <div class="row">
                                <div class="col-md-6 mb-3">
                                    <label class="form-label">Nome Istanza</label>
                                    <input type="text" class="form-control" name="name" required 
                                           placeholder="es. office, remote">
                                </div>
                                <div class="col-md-3 mb-3">
                                    <label class="form-label">Porta</label>
                                    <input type="number" class="form-control" name="port" 
                                           value="1194" min="1" max="65535" required>
                                </div>
                                <div class="col-md-3 mb-3">
                                    <label class="form-label">Protocollo</label>
                                    <select class="form-select" name="protocol">
                                        <option value="udp" selected>UDP</option>
                                        <option value="tcp">TCP</option>
                                    </select>
                                </div>
                            </div>
                            
                            <div class="row">
                                <div class="col-md-6 mb-3">
                                    <label class="form-label">Subnet VPN</label>
                                    <input type="text" class="form-control" name="subnet" 
                                           value="10.8.0.0/24" required placeholder="es. 10.8.0.0/24">
                                </div>
                                <div class="col-md-6 mb-3">
                                    <label class="form-label">Endpoint (IP/Domain pubblico)</label>
                                    <input type="text" class="form-control" name="endpoint" 
                                           placeholder="Lascia vuoto per auto-detect">
                                </div>
                            </div>
                            
                            <div class="mb-3">
                                <label class="form-label">Modalità Tunnel</label>
                                <div class="row g-2">
                                    <div class="col-6">
                                        <input type="radio" class="btn-check" name="tunnel_mode" 
                                               id="tunnel-full" value="full" checked>
                                        <label class="btn btn-outline-primary w-100 text-start py-2 d-block" 
                                               for="tunnel-full">
                                            <i class="ti ti-world me-2"></i><strong>Full Tunnel</strong><br>
                                            <small class="opacity-75">Tutto il traffico passa dalla VPN</small>
                                        </label>
                                    </div>
                                    <div class="col-6">
                                        <input type="radio" class="btn-check" name="tunnel_mode" 
                                               id="tunnel-split" value="split">
                                        <label class="btn btn-outline-primary w-100 text-start py-2 d-block" 
                                               for="tunnel-split">
                                            <i class="ti ti-route me-2"></i><strong>Split Tunnel</strong><br>
                                            <small class="opacity-75">Solo reti specifiche via VPN</small>
                                        </label>
                                    </div>
                                </div>
                            </div>
                            
                            <!-- Split tunnel routes -->
                            <div id="split-tunnel-options" class="d-none mb-3">
                                <label class="form-label">Reti da instradare</label>
                                <div id="routes-list">
                                    <div class="route-row mb-2 d-flex gap-2">
                                        <input type="text" class="form-control route-input" 
                                               placeholder="es. 192.168.1.0/24">
                                        <button type="button" class="btn btn-outline-danger btn-remove-route">
                                            <i class="ti ti-trash"></i>
                                        </button>
                                    </div>
                                </div>
                                <button type="button" class="btn btn-outline-secondary btn-sm" id="btn-add-route">
                                    <i class="ti ti-plus me-1"></i>Aggiungi Rete
                                </button>
                            </div>
                            
                            <!-- Full tunnel options -->
                            <div id="full-tunnel-options" class="mb-3">
                                <label class="form-label">Server DNS</label>
                                <input type="text" class="form-control" name="dns_servers" 
                                       value="8.8.8.8, 1.1.1.1" placeholder="Separati da virgola">
                            </div>
                            
                            <!-- Advanced options -->
                            <details class="mb-3">
                                <summary class="text-muted cursor-pointer">
                                    <i class="ti ti-settings me-1"></i>Opzioni Avanzate
                                </summary>
                                <div class="mt-3 ps-3">
                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Cipher</label>
                                            <select class="form-select" name="cipher">
                                                <option value="AES-256-GCM" selected>AES-256-GCM (raccomandato)</option>
                                                <option value="AES-128-GCM">AES-128-GCM</option>
                                                <option value="CHACHA20-POLY1305">CHACHA20-POLY1305</option>
                                            </select>
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Durata Certificati (giorni)</label>
                                            <input type="number" class="form-control" name="cert_duration_days" 
                                                   value="3650" min="365" max="36500">
                                            <small class="text-muted">Default: 10 anni</small>
                                        </div>
                                    </div>
                                </div>
                            </details>
                        </form>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn" data-bs-dismiss="modal">Annulla</button>
                        <button type="button" class="btn btn-primary" id="btn-save-instance">
                            <i class="ti ti-check me-1"></i>Crea Istanza
                        </button>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Create Client Modal -->
        <div class="modal modal-blur fade" id="modal-create-client" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Nuovo Client</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <form id="form-create-client">
                            <div class="mb-3">
                                <label class="form-label">Nome Client</label>
                                <input type="text" class="form-control" name="name" required 
                                       pattern="[a-zA-Z0-9_-]+" placeholder="es. laptop_mario">
                                <small class="text-muted">Solo lettere, numeri, - e _</small>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Durata Certificato (giorni)</label>
                                <input type="number" class="form-control" name="cert_duration_days" 
                                       placeholder="Lascia vuoto per usare default istanza">
                            </div>
                        </form>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn" data-bs-dismiss="modal">Annulla</button>
                        <button type="button" class="btn btn-primary" id="btn-save-client">
                            <i class="ti ti-check me-1"></i>Crea Client
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;
}

/**
 * Load and display instances
 */
async function loadInstances() {
    try {
        const response = await fetch(`${MODULE_BASE}/instances`);
        const instances = await response.json();

        const container = document.getElementById('instances-container');

        if (instances.length === 0) {
            container.innerHTML = `
                <div class="card">
                    <div class="card-body text-center py-5">
                        <div class="mb-3">
                            <i class="ti ti-lock" style="font-size: 48px; opacity: 0.5;"></i>
                        </div>
                        <h3>Nessuna istanza OpenVPN</h3>
                        <p class="text-muted">Crea la tua prima istanza VPN per iniziare</p>
                        <button class="btn btn-primary" onclick="document.getElementById('btn-create-instance').click()">
                            <i class="ti ti-plus me-2"></i>Crea Istanza
                        </button>
                    </div>
                </div>
            `;
            return;
        }

        container.innerHTML = `
            <div class="row row-cards">
                ${instances.map(inst => renderInstanceCard(inst)).join('')}
            </div>
        `;
    } catch (error) {
        console.error('Error loading instances:', error);
        showToast('Errore nel caricamento delle istanze', 'danger');
    }
}

/**
 * Render instance card
 */
function renderInstanceCard(instance) {
    const isRunning = instance.status === 'running';
    const certWarning = instance.server_cert_expiry &&
        getDaysRemaining(instance.server_cert_expiry) < 30;

    return `
        <div class="col-md-6 col-lg-4">
            <div class="card">
                <div class="card-status-top ${isRunning ? 'bg-success' : 'bg-secondary'}"></div>
                <div class="card-header">
                    <h3 class="card-title">
                        <i class="ti ti-lock me-2"></i>
                        ${escapeHtml(instance.name)}
                    </h3>
                    <div class="card-actions">
                        <span class="badge ${isRunning ? 'bg-success' : 'bg-secondary'}">
                            ${isRunning ? 'Running' : 'Stopped'}
                        </span>
                    </div>
                </div>
                <div class="card-body">
                    <div class="datagrid">
                        <div class="datagrid-item">
                            <div class="datagrid-title">Porta</div>
                            <div class="datagrid-content">${instance.port}/${instance.protocol.toUpperCase()}</div>
                        </div>
                        <div class="datagrid-item">
                            <div class="datagrid-title">Subnet</div>
                            <div class="datagrid-content">${instance.subnet}</div>
                        </div>
                        <div class="datagrid-item">
                            <div class="datagrid-title">Modalità</div>
                            <div class="datagrid-content">
                                <span class="badge bg-${instance.tunnel_mode === 'full' ? 'primary' : 'info'}">
                                    ${instance.tunnel_mode === 'full' ? 'Full Tunnel' : 'Split Tunnel'}
                                </span>
                            </div>
                        </div>
                        <div class="datagrid-item">
                            <div class="datagrid-title">Client</div>
                            <div class="datagrid-content">${instance.client_count}</div>
                        </div>
                    </div>
                    ${certWarning ? `
                        <div class="alert alert-warning mt-3 mb-0 py-2">
                            <i class="ti ti-alert-triangle me-1"></i>
                            Certificato in scadenza!
                        </div>
                    ` : ''}
                </div>
                <div class="card-footer d-flex gap-2">
                    ${isRunning ? `
                        <button class="btn btn-outline-danger btn-sm" 
                                onclick="stopInstance('${instance.id}')">
                            <i class="ti ti-player-stop me-1"></i>Stop
                        </button>
                    ` : `
                        <button class="btn btn-outline-success btn-sm" 
                                onclick="startInstance('${instance.id}')">
                            <i class="ti ti-player-play me-1"></i>Start
                        </button>
                    `}
                    <button class="btn btn-primary btn-sm ms-auto" 
                            onclick="showInstanceDetail('${instance.id}')">
                        <i class="ti ti-settings me-1"></i>Gestisci
                    </button>
                </div>
            </div>
        </div>
    `;
}

/**
 * Show instance detail modal
 */
async function showInstanceDetail(instanceId) {
    currentInstance = instanceId;

    try {
        const [instance, clients, pkiStatus] = await Promise.all([
            fetch(`${MODULE_BASE}/instances/${instanceId}`).then(r => r.json()),
            fetch(`${MODULE_BASE}/instances/${instanceId}/clients`).then(r => r.json()),
            fetch(`${MODULE_BASE}/instances/${instanceId}/pki/status`).then(r => r.json())
        ]);

        document.getElementById('modal-instance-title').textContent = instance.name;
        document.getElementById('modal-instance-body').innerHTML = `
            <ul class="nav nav-tabs" role="tablist">
                <li class="nav-item">
                    <a class="nav-link active" data-bs-toggle="tab" href="#tab-overview">
                        <i class="ti ti-info-circle me-1"></i>Overview
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" data-bs-toggle="tab" href="#tab-clients">
                        <i class="ti ti-users me-1"></i>Client (${clients.length})
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" data-bs-toggle="tab" href="#tab-pki">
                        <i class="ti ti-certificate me-1"></i>PKI
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" data-bs-toggle="tab" href="#tab-firewall">
                        <i class="ti ti-shield me-1"></i>Firewall
                    </a>
                </li>
            </ul>
            
            <div class="tab-content mt-3">
                <!-- Overview Tab -->
                <div class="tab-pane active" id="tab-overview">
                    ${renderOverviewTab(instance)}
                </div>
                
                <!-- Clients Tab -->
                <div class="tab-pane" id="tab-clients">
                    ${renderClientsTab(clients, instanceId)}
                </div>
                
                <!-- PKI Tab -->
                <div class="tab-pane" id="tab-pki">
                    ${renderPKITab(instance, pkiStatus)}
                </div>
                
                <!-- Firewall Tab -->
                <div class="tab-pane" id="tab-firewall">
                    <div class="text-center py-4">
                        <p class="text-muted">La gestione firewall sarà disponibile a breve</p>
                    </div>
                </div>
            </div>
        `;

        new bootstrap.Modal(document.getElementById('modal-instance-detail')).show();
    } catch (error) {
        console.error('Error loading instance detail:', error);
        showToast('Errore nel caricamento dei dettagli', 'danger');
    }
}

/**
 * Render overview tab
 */
function renderOverviewTab(instance) {
    return `
        <div class="row">
            <div class="col-md-6">
                <div class="datagrid">
                    <div class="datagrid-item">
                        <div class="datagrid-title">ID</div>
                        <div class="datagrid-content"><code>${instance.id}</code></div>
                    </div>
                    <div class="datagrid-item">
                        <div class="datagrid-title">Porta</div>
                        <div class="datagrid-content">${instance.port}/${instance.protocol.toUpperCase()}</div>
                    </div>
                    <div class="datagrid-item">
                        <div class="datagrid-title">Subnet</div>
                        <div class="datagrid-content">${instance.subnet}</div>
                    </div>
                    <div class="datagrid-item">
                        <div class="datagrid-title">Interfaccia</div>
                        <div class="datagrid-content"><code>${instance.interface}</code></div>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="datagrid">
                    <div class="datagrid-item">
                        <div class="datagrid-title">Modalità Tunnel</div>
                        <div class="datagrid-content">
                            <span class="badge bg-${instance.tunnel_mode === 'full' ? 'primary' : 'info'}">
                                ${instance.tunnel_mode === 'full' ? 'Full Tunnel' : 'Split Tunnel'}
                            </span>
                        </div>
                    </div>
                    <div class="datagrid-item">
                        <div class="datagrid-title">Cipher</div>
                        <div class="datagrid-content">${instance.cipher}</div>
                    </div>
                    <div class="datagrid-item">
                        <div class="datagrid-title">DNS</div>
                        <div class="datagrid-content">${instance.dns_servers.join(', ')}</div>
                    </div>
                    <div class="datagrid-item">
                        <div class="datagrid-title">Endpoint</div>
                        <div class="datagrid-content">${instance.endpoint || 'Auto-detect'}</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="mt-4">
            <button class="btn btn-outline-primary" onclick="editRouting('${instance.id}')">
                <i class="ti ti-route me-1"></i>Modifica Routing
            </button>
            <button class="btn btn-outline-danger ms-2" onclick="deleteInstance('${instance.id}')">
                <i class="ti ti-trash me-1"></i>Elimina Istanza
            </button>
        </div>
    `;
}

/**
 * Render clients tab
 */
function renderClientsTab(clients, instanceId) {
    return `
        <div class="mb-3">
            <button class="btn btn-primary" onclick="showCreateClientModal('${instanceId}')">
                <i class="ti ti-user-plus me-1"></i>Nuovo Client
            </button>
        </div>
        
        ${clients.length === 0 ? `
            <div class="text-center py-4">
                <p class="text-muted">Nessun client configurato</p>
            </div>
        ` : `
            <div class="table-responsive">
                <table class="table table-vcenter card-table">
                    <thead>
                        <tr>
                            <th>Nome</th>
                            <th>IP</th>
                            <th>Stato</th>
                            <th>Certificato</th>
                            <th>Azioni</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${clients.map(client => `
                            <tr class="${client.revoked ? 'text-muted' : ''}">
                                <td>
                                    <strong>${escapeHtml(client.name)}</strong>
                                    ${client.revoked ? '<span class="badge bg-danger ms-1">Revocato</span>' : ''}
                                </td>
                                <td><code>${client.allocated_ip}</code></td>
                                <td>
                                    ${client.is_connected ?
            '<span class="badge bg-success">Connesso</span>' :
            '<span class="badge bg-secondary">Offline</span>'}
                                </td>
                                <td>
                                    ${renderCertStatus(client.cert_days_remaining, client.revoked)}
                                </td>
                                <td>
                                    ${!client.revoked ? `
                                        <div class="btn-group btn-group-sm">
                                            <a href="${MODULE_BASE}/instances/${instanceId}/clients/${client.name}/config" 
                                               class="btn btn-outline-primary" title="Download Config">
                                                <i class="ti ti-download"></i>
                                            </a>
                                            <button class="btn btn-outline-secondary" 
                                                    onclick="showClientQR('${instanceId}', '${client.name}')"
                                                    title="QR Code">
                                                <i class="ti ti-qrcode"></i>
                                            </button>
                                            <button class="btn btn-outline-warning" 
                                                    onclick="renewClientCert('${instanceId}', '${client.name}')"
                                                    title="Rinnova Certificato">
                                                <i class="ti ti-refresh"></i>
                                            </button>
                                            <button class="btn btn-outline-danger" 
                                                    onclick="revokeClient('${instanceId}', '${client.name}')"
                                                    title="Revoca">
                                                <i class="ti ti-trash"></i>
                                            </button>
                                        </div>
                                    ` : ''}
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `}
    `;
}

/**
 * Render PKI tab
 */
function renderPKITab(instance, pkiStatus) {
    return `
        <div class="row">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h4 class="card-title">Certificato Server</h4>
                    </div>
                    <div class="card-body">
                        <div class="datagrid">
                            <div class="datagrid-item">
                                <div class="datagrid-title">Scadenza</div>
                                <div class="datagrid-content">
                                    ${instance.server_cert_expiry ?
            formatDate(instance.server_cert_expiry) : 'N/A'}
                                </div>
                            </div>
                            <div class="datagrid-item">
                                <div class="datagrid-title">Giorni Rimanenti</div>
                                <div class="datagrid-content">
                                    ${renderCertStatus(pkiStatus.server_cert_days_remaining, false)}
                                </div>
                            </div>
                        </div>
                        <button class="btn btn-warning mt-3" 
                                onclick="renewServerCert('${instance.id}')">
                            <i class="ti ti-refresh me-1"></i>Rinnova Certificato Server
                        </button>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h4 class="card-title">Certificate Authority</h4>
                    </div>
                    <div class="card-body">
                        <div class="datagrid">
                            <div class="datagrid-item">
                                <div class="datagrid-title">Scadenza CA</div>
                                <div class="datagrid-content">
                                    ${pkiStatus.ca_expiry ? formatDate(pkiStatus.ca_expiry) : 'N/A'}
                                </div>
                            </div>
                            <div class="datagrid-item">
                                <div class="datagrid-title">Client Revocati</div>
                                <div class="datagrid-content">${pkiStatus.revoked_clients_count}</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

/**
 * Render certificate status badge
 */
function renderCertStatus(daysRemaining, revoked) {
    if (revoked) {
        return '<span class="badge bg-danger">Revocato</span>';
    }
    if (daysRemaining === null || daysRemaining === undefined) {
        return '<span class="badge bg-secondary">N/A</span>';
    }
    if (daysRemaining < 0) {
        return '<span class="badge bg-danger">Scaduto</span>';
    }
    if (daysRemaining < 30) {
        return `<span class="badge bg-warning">${daysRemaining} giorni</span>`;
    }
    if (daysRemaining < 90) {
        return `<span class="badge bg-info">${daysRemaining} giorni</span>`;
    }
    return `<span class="badge bg-success">${daysRemaining} giorni</span>`;
}

// =============================================================================
// EVENT LISTENERS
// =============================================================================

function setupEventListeners() {
    // Create instance button
    document.getElementById('btn-create-instance').addEventListener('click', () => {
        document.getElementById('form-create-instance').reset();
        document.getElementById('split-tunnel-options').classList.add('d-none');
        document.getElementById('full-tunnel-options').classList.remove('d-none');
        new bootstrap.Modal(document.getElementById('modal-create-instance')).show();
    });

    // Tunnel mode toggle
    document.querySelectorAll('input[name="tunnel_mode"]').forEach(radio => {
        radio.addEventListener('change', (e) => {
            const isSplit = e.target.value === 'split';
            document.getElementById('split-tunnel-options').classList.toggle('d-none', !isSplit);
            document.getElementById('full-tunnel-options').classList.toggle('d-none', isSplit);
        });
    });

    // Add route button
    document.getElementById('btn-add-route')?.addEventListener('click', () => {
        const list = document.getElementById('routes-list');
        const row = document.createElement('div');
        row.className = 'route-row mb-2 d-flex gap-2';
        row.innerHTML = `
            <input type="text" class="form-control route-input" placeholder="es. 192.168.1.0/24">
            <button type="button" class="btn btn-outline-danger btn-remove-route">
                <i class="ti ti-trash"></i>
            </button>
        `;
        list.appendChild(row);
    });

    // Remove route buttons (delegated)
    document.getElementById('routes-list')?.addEventListener('click', (e) => {
        if (e.target.closest('.btn-remove-route')) {
            const rows = document.querySelectorAll('.route-row');
            if (rows.length > 1) {
                e.target.closest('.route-row').remove();
            }
        }
    });

    // Save instance
    document.getElementById('btn-save-instance').addEventListener('click', createInstance);

    // Save client
    document.getElementById('btn-save-client').addEventListener('click', createClient);
}

// =============================================================================
// API FUNCTIONS
// =============================================================================

async function createInstance() {
    const form = document.getElementById('form-create-instance');
    const formData = new FormData(form);

    const data = {
        name: formData.get('name'),
        port: parseInt(formData.get('port')),
        protocol: formData.get('protocol'),
        subnet: formData.get('subnet'),
        tunnel_mode: formData.get('tunnel_mode'),
        cipher: formData.get('cipher'),
        cert_duration_days: parseInt(formData.get('cert_duration_days')) || 3650,
        endpoint: formData.get('endpoint') || null,
        dns_servers: formData.get('dns_servers')?.split(',').map(s => s.trim()).filter(Boolean) || [],
        routes: []
    };

    if (data.tunnel_mode === 'split') {
        document.querySelectorAll('.route-input').forEach(input => {
            if (input.value.trim()) {
                data.routes.push({ network: input.value.trim() });
            }
        });
    }

    try {
        const response = await fetch(`${MODULE_BASE}/instances`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Errore nella creazione');
        }

        bootstrap.Modal.getInstance(document.getElementById('modal-create-instance')).hide();
        showToast('Istanza creata con successo', 'success');
        await loadInstances();
    } catch (error) {
        showToast(error.message, 'danger');
    }
}

async function startInstance(instanceId) {
    try {
        const response = await fetch(`${MODULE_BASE}/instances/${instanceId}/start`, {
            method: 'POST'
        });
        if (!response.ok) throw new Error('Errore avvio istanza');
        showToast('Istanza avviata', 'success');
        await loadInstances();
    } catch (error) {
        showToast(error.message, 'danger');
    }
}

async function stopInstance(instanceId) {
    try {
        const response = await fetch(`${MODULE_BASE}/instances/${instanceId}/stop`, {
            method: 'POST'
        });
        if (!response.ok) throw new Error('Errore arresto istanza');
        showToast('Istanza fermata', 'success');
        await loadInstances();
    } catch (error) {
        showToast(error.message, 'danger');
    }
}

async function deleteInstance(instanceId) {
    if (!confirm('Sei sicuro di voler eliminare questa istanza?')) return;

    try {
        const response = await fetch(`${MODULE_BASE}/instances/${instanceId}`, {
            method: 'DELETE'
        });
        if (!response.ok) throw new Error('Errore eliminazione istanza');

        bootstrap.Modal.getInstance(document.getElementById('modal-instance-detail')).hide();
        showToast('Istanza eliminata', 'success');
        await loadInstances();
    } catch (error) {
        showToast(error.message, 'danger');
    }
}

function showCreateClientModal(instanceId) {
    currentInstance = instanceId;
    document.getElementById('form-create-client').reset();
    new bootstrap.Modal(document.getElementById('modal-create-client')).show();
}

async function createClient() {
    const form = document.getElementById('form-create-client');
    const formData = new FormData(form);

    const data = {
        name: formData.get('name'),
        cert_duration_days: formData.get('cert_duration_days') ?
            parseInt(formData.get('cert_duration_days')) : null
    };

    try {
        const response = await fetch(`${MODULE_BASE}/instances/${currentInstance}/clients`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Errore nella creazione');
        }

        bootstrap.Modal.getInstance(document.getElementById('modal-create-client')).hide();
        showToast('Client creato con successo', 'success');
        showInstanceDetail(currentInstance);
    } catch (error) {
        showToast(error.message, 'danger');
    }
}

async function revokeClient(instanceId, clientName) {
    if (!confirm(`Sei sicuro di voler revocare il client "${clientName}"?`)) return;

    try {
        const response = await fetch(
            `${MODULE_BASE}/instances/${instanceId}/clients/${clientName}`,
            { method: 'DELETE' }
        );
        if (!response.ok) throw new Error('Errore revoca client');
        showToast('Client revocato', 'success');
        showInstanceDetail(instanceId);
    } catch (error) {
        showToast(error.message, 'danger');
    }
}

async function renewClientCert(instanceId, clientName) {
    if (!confirm(`Rinnovare il certificato per "${clientName}"? Il client dovrà riscaricare la configurazione.`)) return;

    try {
        const response = await fetch(
            `${MODULE_BASE}/instances/${instanceId}/clients/${clientName}/renew`,
            { method: 'POST' }
        );
        if (!response.ok) throw new Error('Errore rinnovo certificato');
        showToast('Certificato rinnovato', 'success');
        showInstanceDetail(instanceId);
    } catch (error) {
        showToast(error.message, 'danger');
    }
}

async function renewServerCert(instanceId) {
    if (!confirm('Rinnovare il certificato server? L\'istanza verrà riavviata.')) return;

    try {
        const response = await fetch(
            `${MODULE_BASE}/instances/${instanceId}/pki/renew-server`,
            { method: 'POST' }
        );
        if (!response.ok) throw new Error('Errore rinnovo certificato');
        showToast('Certificato server rinnovato', 'success');
        showInstanceDetail(instanceId);
    } catch (error) {
        showToast(error.message, 'danger');
    }
}

async function showClientQR(instanceId, clientName) {
    window.open(`${MODULE_BASE}/instances/${instanceId}/clients/${clientName}/qr`, '_blank');
}

// =============================================================================
// UTILITIES
// =============================================================================

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatDate(dateStr) {
    if (!dateStr) return 'N/A';
    return new Date(dateStr).toLocaleDateString('it-IT', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
    });
}

function getDaysRemaining(dateStr) {
    if (!dateStr) return null;
    const expiry = new Date(dateStr);
    const now = new Date();
    return Math.floor((expiry - now) / (1000 * 60 * 60 * 24));
}

function showToast(message, type = 'info') {
    // Use MADMIN's toast system if available
    if (window.showGlobalToast) {
        window.showGlobalToast(message, type);
    } else {
        alert(message);
    }
}

// Initialize on load
init();
