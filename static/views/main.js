/**
 * OpenVPN Module - Main View
 * 
 * Complete management UI for OpenVPN VPN instances and clients.
 * Layout matches WireGuard module for consistency.
 */

import { apiGet, apiPost, apiDelete, apiPatch } from '/static/js/api.js';
import { showToast, confirmDialog, loadingSpinner } from '/static/js/utils.js';
import { checkPermission } from '/static/js/app.js';

const MODULE_API = '/modules/openvpn';

let currentInstanceId = null;
let networkInterfaces = [];  // Cache for system network interfaces
let canManage = false;  // Permission cache
let canClients = false;

// Helper function to format bytes to human readable string
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// Helper function to format ISO timestamp to "X ago" format
function formatTimeAgo(isoString) {
    if (!isoString) return 'Mai';
    const date = new Date(isoString);
    const now = new Date();
    const diffMs = now - date;
    const diffSec = Math.floor(diffMs / 1000);

    if (diffSec < 60) return 'Adesso';
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)} min fa`;
    if (diffSec < 86400) return `${Math.floor(diffSec / 3600)} ore fa`;
    if (diffSec < 604800) return `${Math.floor(diffSec / 86400)} giorni fa`;
    return date.toLocaleDateString('it-IT');
}

// Helper function to escape HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

export async function render(container, params) {
    // Cache permissions
    canManage = checkPermission('openvpn.manage');
    canClients = checkPermission('openvpn.clients');

    if (params && params.length > 0) {
        currentInstanceId = params[0];
        await renderInstanceDetail(container);
    } else {
        await renderInstanceList(container);
    }
}

// ============== INSTANCE LIST ==============

async function renderInstanceList(container) {
    container.innerHTML = `
        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h3 class="card-title"><i class="ti ti-lock me-2"></i>Istanze OpenVPN</h3>
                ${canManage ? `
                <button class="btn btn-primary" id="btn-new-instance">
                    <i class="ti ti-plus me-1"></i>Nuova Istanza
                </button>` : ''}
            </div>
            <div class="card-body" id="instances-list">${loadingSpinner()}</div>
        </div>
        
        <!-- New Instance Modal -->
        <div class="modal fade" id="modal-new-instance" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Nuova Istanza OpenVPN</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label class="form-label">Nome</label>
                                <input type="text" class="form-control" id="new-instance-name" placeholder="Office VPN">
                            </div>
                            <div class="col-md-3 mb-3">
                                <label class="form-label">Porta</label>
                                <input type="number" class="form-control" id="new-instance-port" value="1194">
                            </div>
                            <div class="col-md-3 mb-3">
                                <label class="form-label">Protocollo</label>
                                <select class="form-select" id="new-instance-protocol">
                                    <option value="udp">UDP</option>
                                    <option value="tcp" selected>TCP</option>
                                </select>
                            </div>
                        </div>
                        
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label class="form-label">Subnet VPN</label>
                                <input type="text" class="form-control" id="new-instance-subnet" placeholder="10.8.0.0/24">
                            </div>
                            <div class="col-md-6 mb-3">
                                <label class="form-label">Endpoint (IP/Domain pubblico)</label>
                                <input type="text" class="form-control" id="new-instance-endpoint" placeholder="Lascia vuoto per auto-detect">
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">Modalità Tunnel</label>
                            <div class="row g-2">
                                <div class="col-6">
                                    <input type="radio" class="btn-check" name="tunnel-mode" id="tunnel-full" value="full" checked>
                                    <label class="btn btn-outline-primary w-100 text-start py-2 d-block" for="tunnel-full">
                                        <i class="ti ti-world me-2"></i><strong>Full Tunnel</strong><br>
                                        <small class="opacity-75">Tutto il traffico passa dalla VPN</small>
                                    </label>
                                </div>
                                <div class="col-6">
                                    <input type="radio" class="btn-check" name="tunnel-mode" id="tunnel-split" value="split">
                                    <label class="btn btn-outline-primary w-100 text-start py-2 d-block" for="tunnel-split">
                                        <i class="ti ti-route me-2"></i><strong>Split Tunnel</strong><br>
                                        <small class="opacity-75">Solo reti specifiche via VPN</small>
                                    </label>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Full Tunnel Options -->
                        <div id="full-tunnel-options">
                            <div class="mb-3">
                                <label class="form-label">Server DNS</label>
                                <input type="text" class="form-control" id="new-instance-dns" 
                                       placeholder="8.8.8.8, 1.1.1.1" value="8.8.8.8, 1.1.1.1">
                                <small class="form-hint">Separati da virgola. Lascia vuoto per usare Google DNS.</small>
                            </div>
                        </div>
                        
                        <!-- Split Tunnel Options -->
                        <div id="split-tunnel-options" style="display: none;">
                            <div class="mb-3">
                                <label class="form-label">Rotte da inoltrare</label>
                                <div id="routes-container">
                                    <div class="route-row mb-2 d-flex gap-2 align-items-center">
                                        <input type="text" class="form-control route-network" placeholder="192.168.1.0/24" style="flex: 2">
                                        <button class="btn btn-outline-success btn-add-route" type="button">
                                            <i class="ti ti-plus"></i>
                                        </button>
                                    </div>
                                </div>
                                <small class="form-hint">Subnet da instradare tramite VPN.</small>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Server DNS (opzionale)</label>
                                <input type="text" class="form-control" id="new-instance-dns-split" placeholder="Lascia vuoto per usare DNS locali">
                            </div>
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
                                        <select class="form-select" id="new-instance-cipher">
                                            <option value="AES-256-GCM" selected>AES-256-GCM (raccomandato)</option>
                                            <option value="AES-128-GCM">AES-128-GCM</option>
                                            <option value="CHACHA20-POLY1305">CHACHA20-POLY1305</option>
                                        </select>
                                    </div>
                                    <div class="col-md-6 mb-3">
                                        <label class="form-label">Durata Certificati (giorni)</label>
                                        <input type="number" class="form-control" id="new-instance-cert-days" 
                                               value="3650" min="365" max="36500">
                                        <small class="form-hint">Default: 10 anni</small>
                                    </div>
                                </div>
                            </div>
                        </details>
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-outline-secondary" data-bs-dismiss="modal">Annulla</button>
                        <button class="btn btn-primary" id="btn-create-instance">
                            <i class="ti ti-check me-1"></i>Crea Istanza
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;

    await loadInstances();
    setupCreateForm();
}

async function setupCreateForm() {
    document.getElementById('btn-new-instance')?.addEventListener('click', async () => {
        new bootstrap.Modal(document.getElementById('modal-new-instance')).show();
    });

    // Toggle tunnel options
    document.querySelectorAll('input[name="tunnel-mode"]').forEach(radio => {
        radio.addEventListener('change', (e) => {
            const fullOpts = document.getElementById('full-tunnel-options');
            const splitOpts = document.getElementById('split-tunnel-options');
            if (e.target.value === 'full') {
                fullOpts.style.display = 'block';
                splitOpts.style.display = 'none';
            } else {
                fullOpts.style.display = 'none';
                splitOpts.style.display = 'block';
            }
        });
    });

    // Add route button
    document.querySelector('.btn-add-route')?.addEventListener('click', addRouteInput);

    document.getElementById('btn-create-instance')?.addEventListener('click', createInstance);
}

function addRouteInput() {
    const container = document.getElementById('routes-container');
    const div = document.createElement('div');
    div.className = 'route-row mb-2 d-flex gap-2 align-items-center';
    div.innerHTML = `
        <input type="text" class="form-control route-network" placeholder="192.168.1.0/24" style="flex: 2">
        <button class="btn btn-outline-danger btn-remove-route" type="button">
            <i class="ti ti-minus"></i>
        </button>
    `;
    div.querySelector('.btn-remove-route').addEventListener('click', () => div.remove());
    container.appendChild(div);
}

async function loadInstances() {
    const listEl = document.getElementById('instances-list');
    try {
        const instances = await apiGet(`${MODULE_API}/instances`);

        if (instances.length === 0) {
            listEl.innerHTML = `<div class="text-center py-5 text-muted">
                <i class="ti ti-server-off" style="font-size: 3rem;"></i>
                <p class="mt-2">Nessuna istanza configurata</p>
                <small>Clicca "Nuova Istanza" per crearne una</small>
            </div>`;
            return;
        }

        listEl.innerHTML = `<div class="table-responsive"><table class="table table-vcenter card-table table-hover">
            <thead><tr>
                <th style="width: 30px;"></th>
                <th>Nome</th><th>Interfaccia</th><th>Porta</th><th>Subnet</th>
                <th>Modalità</th><th>Client</th><th class="w-1"></th>
            </tr></thead>
            <tbody>${instances.map(i => `<tr class="instance-row" data-id="${i.id}" style="cursor: pointer;">
                <td>
                    <span class="status-dot ${i.status === 'running' ? 'status-dot-animated bg-success' : 'bg-secondary'}" 
                          title="${i.status === 'running' ? 'Attivo' : 'Fermo'}"></span>
                </td>
                <td>
                    <a href="#openvpn/${i.id}" class="text-reset">
                        <strong>${escapeHtml(i.name)}</strong>
                    </a>
                    <div class="small text-muted">
                        ${i.status === 'running'
                ? '<span class="text-success">Attivo</span>'
                : '<span class="text-secondary">Fermo</span>'}
                    </div>
                </td>
                <td><code>${i.interface}</code></td>
                <td>${i.port}/${i.protocol.toUpperCase()}</td>
                <td><code>${i.subnet}</code></td>
                <td><span class="badge ${i.tunnel_mode === 'full' ? 'bg-blue' : 'bg-purple'}-lt">
                    ${i.tunnel_mode === 'full' ? 'Full' : 'Split'}
                </span></td>
                <td>${i.client_count}</td>
                <td>
                    <div class="btn-group btn-group-sm" onclick="event.stopPropagation();">
                        ${canManage ? (i.status === 'running'
                ? `<button class="btn btn-ghost-warning btn-stop" data-id="${i.id}" title="Ferma"><i class="ti ti-player-stop"></i></button>`
                : `<button class="btn btn-ghost-success btn-start" data-id="${i.id}" title="Avvia"><i class="ti ti-player-play"></i></button>`) : ''}
                        ${canManage ? `<button class="btn btn-ghost-danger btn-delete" data-id="${i.id}" title="Elimina"><i class="ti ti-trash"></i></button>` : ''}
                    </div>
                </td>
            </tr>`).join('')}</tbody>
        </table></div>`;

        setupInstanceRowActions();
    } catch (err) {
        listEl.innerHTML = `<div class="alert alert-danger">${err.message}</div>`;
    }
}

function setupInstanceRowActions() {
    // Row click navigates to detail
    document.querySelectorAll('.instance-row').forEach(row => {
        row.addEventListener('click', (e) => {
            if (e.target.closest('.btn-group')) return;
            window.location.hash = `#openvpn/${row.dataset.id}`;
        });
    });

    // Start instance
    document.querySelectorAll('.btn-start').forEach(btn => {
        btn.addEventListener('click', async () => {
            const id = btn.dataset.id;
            try {
                await apiPost(`${MODULE_API}/instances/${id}/start`);
                showToast('Istanza avviata', 'success');
                loadInstances();
            } catch (err) {
                showToast(err.message, 'error');
            }
        });
    });

    // Stop instance
    document.querySelectorAll('.btn-stop').forEach(btn => {
        btn.addEventListener('click', async () => {
            const id = btn.dataset.id;
            try {
                await apiPost(`${MODULE_API}/instances/${id}/stop`);
                showToast('Istanza fermata', 'success');
                loadInstances();
            } catch (err) {
                showToast(err.message, 'error');
            }
        });
    });

    // Delete instance
    document.querySelectorAll('.btn-delete').forEach(btn => {
        btn.addEventListener('click', async () => {
            const id = btn.dataset.id;
            if (!await confirmDialog('Eliminare questa istanza VPN?', 'Tutti i client e certificati saranno eliminati.')) return;
            try {
                await apiDelete(`${MODULE_API}/instances/${id}`);
                showToast('Istanza eliminata', 'success');
                loadInstances();
            } catch (err) {
                showToast(err.message, 'error');
            }
        });
    });
}

async function createInstance() {
    const name = document.getElementById('new-instance-name').value.trim();
    const port = parseInt(document.getElementById('new-instance-port').value);
    const protocol = document.getElementById('new-instance-protocol').value;
    const subnet = document.getElementById('new-instance-subnet').value.trim();
    const endpoint = document.getElementById('new-instance-endpoint').value.trim() || null;
    const tunnelMode = document.querySelector('input[name="tunnel-mode"]:checked').value;
    const cipher = document.getElementById('new-instance-cipher').value;
    const certDays = parseInt(document.getElementById('new-instance-cert-days').value) || 3650;

    if (!name || !port || !subnet) {
        showToast('Compila tutti i campi obbligatori', 'error');
        return;
    }

    // Collect DNS servers
    let dnsInput = tunnelMode === 'full'
        ? document.getElementById('new-instance-dns').value
        : document.getElementById('new-instance-dns-split').value;

    let dnsServers = dnsInput.split(',').map(s => s.trim()).filter(s => s);
    if (dnsServers.length === 0 && tunnelMode === 'full') {
        dnsServers = ['8.8.8.8', '1.1.1.1'];
    }

    // Collect routes for split tunnel
    let routes = [];
    if (tunnelMode === 'split') {
        document.querySelectorAll('.route-row').forEach(row => {
            const network = row.querySelector('.route-network')?.value.trim();
            if (network) {
                routes.push({ network });
            }
        });
    }

    try {
        await apiPost(`${MODULE_API}/instances`, {
            name, port, protocol, subnet, endpoint,
            tunnel_mode: tunnelMode,
            dns_servers: dnsServers,
            routes: routes,
            cipher: cipher,
            cert_duration_days: certDays
        });
        showToast('Istanza creata con successo', 'success');
        bootstrap.Modal.getInstance(document.getElementById('modal-new-instance'))?.hide();
        await loadInstances();
    } catch (err) {
        showToast(err.message, 'error');
    }
}

// ============== INSTANCE DETAIL ==============

async function renderInstanceDetail(container) {
    try {
        const instance = await apiGet(`${MODULE_API}/instances/${currentInstanceId}`);
        const clients = await apiGet(`${MODULE_API}/instances/${currentInstanceId}/clients`);

        container.innerHTML = `
            <div class="mb-3">
                <a href="#openvpn" class="text-muted">
                    <i class="ti ti-arrow-left me-1"></i>Torna alle istanze
                </a>
            </div>
            
            <!-- Instance Info Card -->
            <div class="card mb-3">
                <div class="card-header">
                    <div class="d-flex justify-content-between align-items-center w-100">
                        <div>
                            <h3 class="card-title mb-0">${escapeHtml(instance.name)}</h3>
                            <small class="text-muted">Interfaccia: ${instance.interface}</small>
                        </div>
                        <div class="btn-group">
                            ${canManage ? `
                            <button class="btn ${instance.status === 'running' ? 'btn-warning' : 'btn-success'}" 
                                    onclick="${instance.status === 'running' ? 'stopInstance' : 'startInstance'}('${instance.id}')">
                                <i class="ti ti-player-${instance.status === 'running' ? 'stop' : 'play'} me-1"></i>
                                ${instance.status === 'running' ? 'Ferma' : 'Avvia'}
                            </button>
                            <button class="btn btn-outline-danger" onclick="deleteInstance('${instance.id}')">
                                <i class="ti ti-trash"></i>
                            </button>` : ''}
                        </div>
                    </div>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-2">
                            <span class="text-muted">Stato</span><br>
                            <span class="badge ${instance.status === 'running' ? 'bg-success' : 'bg-secondary-lt'} fs-6">
                                ${instance.status === 'running' ? 'Attivo' : 'Fermo'}
                            </span>
                        </div>
                        <div class="col-md-2">
                            <span class="text-muted">Porta</span><br>
                            <strong>${instance.port}/${instance.protocol.toUpperCase()}</strong>
                        </div>
                        <div class="col-md-2">
                            <span class="text-muted">Subnet</span><br>
                            <code>${instance.subnet}</code>
                        </div>
                        <div class="col-md-2">
                            <span class="text-muted">Modalità</span><br>
                            <span id="display-tunnel-mode" class="badge ${instance.tunnel_mode === 'full' ? 'bg-blue' : 'bg-purple'}-lt">
                                ${instance.tunnel_mode === 'full' ? 'Full Tunnel' : 'Split Tunnel'}
                            </span>
                            ${canManage ? `<button class="btn btn-sm btn-ghost-primary p-0 ms-1" id="btn-edit-routing" title="Modifica instradamento">
                                <i class="ti ti-edit fs-5"></i>
                            </button>` : ''}
                        </div>
                        <div class="col-md-2">
                            <span class="text-muted">DNS</span><br>
                            <small>${instance.dns_servers?.join(', ') || 'N/A'}</small>
                        </div>
                        <div class="col-md-2">
                            <span class="text-muted">Client</span><br>
                            <strong>${instance.client_count}</strong>
                        </div>
                    </div>
                    <hr>
                    <div class="row align-items-center">
                        <div class="col-md-10">
                            <span class="text-muted">Endpoint Pubblico:</span>
                            <code id="display-endpoint">${instance.endpoint || '(auto-detect)'}</code>
                        </div>
                        <div class="col-md-2 text-end">
                            <button class="btn btn-sm btn-outline-primary" id="btn-edit-endpoint">
                                <i class="ti ti-edit me-1"></i>Modifica
                            </button>
                        </div>
                    </div>
                    <div id="display-routes-section">
                    ${instance.tunnel_mode === 'split' && instance.routes?.length ? `
                        <hr>
                        <h4>Rotte Split Tunnel</h4>
                        <div class="d-flex flex-wrap gap-2">
                            ${instance.routes.map(r => `<code class="badge bg-light text-dark">${r.network || r}</code>`).join('')}
                        </div>
                    ` : ''}
                    </div>
                </div>
            </div>
            
            <!-- Tabs for Clients, PKI and Firewall -->
            <ul class="nav nav-tabs" role="tablist">
                <li class="nav-item" role="presentation">
                    <button class="nav-link active" id="tab-clients" data-bs-toggle="tab" data-bs-target="#pane-clients" type="button">
                        <i class="ti ti-users me-1"></i>Client (${clients.length})
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="tab-pki" data-bs-toggle="tab" data-bs-target="#pane-pki" type="button">
                        <i class="ti ti-certificate me-1"></i>PKI
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="tab-firewall" data-bs-toggle="tab" data-bs-target="#pane-firewall" type="button">
                        <i class="ti ti-shield me-1"></i>Firewall
                    </button>
                </li>
            </ul>
            
            <div class="tab-content">
                <!-- Clients Tab -->
                <div class="tab-pane fade show active" id="pane-clients" role="tabpanel">
                    <div class="card card-body border-top-0 rounded-top-0">
                        <div class="d-flex justify-content-between align-items-center mb-3">
                            <h4 class="mb-0">Client VPN</h4>
                            ${canClients ? `
                            <button class="btn btn-primary" id="btn-new-client">
                                <i class="ti ti-user-plus me-1"></i>Nuovo Client
                            </button>` : ''}
                        </div>
                        ${clients.length === 0 ? `
                            <div class="text-center py-4 text-muted">
                                <i class="ti ti-users-minus" style="font-size: 2rem;"></i>
                                <p class="mt-2">Nessun client configurato</p>
                                <small>Clicca "Nuovo Client" per aggiungerne uno</small>
                            </div>
                        ` : `
                            <div class="table-responsive">
                                <table class="table table-vcenter">
                                    <thead>
                                        <tr>
                                            <th>Stato</th>
                                            <th>Nome</th>
                                            <th>IP Assegnato</th>
                                            <th>Certificato</th>
                                            <th>Traffico</th>
                                            <th>Connesso da</th>
                                            <th class="w-1">Azioni</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        ${clients.map(c => `
                                            <tr class="${c.revoked ? 'text-muted' : ''}">
                                                <td>
                                                    ${c.is_connected === true
                ? '<span class="status-dot status-dot-animated bg-success" title="Connesso"></span>'
                : '<span class="status-dot bg-secondary" title="Offline"></span>'
            }
                                                </td>
                                                <td>
                                                    <strong>${escapeHtml(c.name)}</strong>
                                                    ${c.revoked ? '<span class="badge bg-danger ms-1">Revocato</span>' : ''}
                                                </td>
                                                <td><code>${c.allocated_ip}</code></td>
                                                <td>${renderCertStatus(c.cert_days_remaining, c.revoked)}</td>
                                                <td>
                                                    ${c.is_connected === true ? `
                                                    <small class="text-muted">
                                                        <i class="ti ti-arrow-down text-success"></i> ${formatBytes(c.bytes_received || 0)}
                                                        <i class="ti ti-arrow-up text-primary ms-2"></i> ${formatBytes(c.bytes_sent || 0)}
                                                    </small>
                                                    ` : '<small class="text-muted">-</small>'}
                                                </td>
                                                <td>
                                                    ${c.last_connection
                ? `<small class="text-muted">${formatTimeAgo(c.last_connection)}</small>`
                : '<small class="text-muted">-</small>'
            }
                                                </td>
                                                <td>
                                                    <div class="btn-group">
                                                        ${!c.revoked && canClients ? `
                                                        <button class="btn btn-sm btn-outline-primary" onclick="downloadConfig('${c.name}')" title="Scarica Config">
                                                            <i class="ti ti-download"></i>
                                                        </button>
                                                        <button class="btn btn-sm btn-outline-success" onclick="openSendEmailModal('${c.name}')" title="Invia via Email">
                                                            <i class="ti ti-mail"></i>
                                                        </button>
                                                        <button class="btn btn-sm btn-outline-warning" onclick="renewClientCert('${c.name}')" title="Rinnova Certificato">
                                                            <i class="ti ti-refresh"></i>
                                                        </button>
                                                        <button class="btn btn-sm btn-outline-danger" onclick="revokeClient('${c.name}')" title="Revoca">
                                                            <i class="ti ti-ban"></i>
                                                        </button>` : ''}
                                                        ${c.revoked && canClients ? `
                                                        <button class="btn btn-sm btn-outline-success" onclick="restoreClient('${c.name}')" title="Ripristina">
                                                            <i class="ti ti-restore"></i>
                                                        </button>
                                                        <button class="btn btn-sm btn-outline-danger" onclick="deleteClientPermanent('${c.name}')" title="Elimina Definitivamente">
                                                            <i class="ti ti-trash"></i>
                                                        </button>` : ''}
                                                    </div>
                                                </td>
                                            </tr>
                                        `).join('')}
                                    </tbody>
                                </table>
                            </div>
                        `}
                    </div>
                </div>
                
                <!-- PKI Tab -->
                <div class="tab-pane fade" id="pane-pki" role="tabpanel">
                    <div class="card card-body border-top-0 rounded-top-0" id="pki-content">
                        <div class="text-center py-4 text-muted">
                            <i class="ti ti-loader ti-spin" style="font-size: 2rem;"></i>
                            <p class="mt-2">Caricamento...</p>
                        </div>
                    </div>
                </div>
                
                <!-- Firewall Tab -->
                <div class="tab-pane fade" id="pane-firewall" role="tabpanel">
                    <div class="card card-body border-top-0 rounded-top-0" id="firewall-content">
                        <div class="text-center py-4 text-muted">
                            <i class="ti ti-loader ti-spin" style="font-size: 2rem;"></i>
                            <p class="mt-2">Caricamento...</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- New Client Modal -->
        <div class="modal" id="modal-new-client" tabindex="-1">
            <div class="modal-dialog modal-sm">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Nuovo Client</h5>
                        <button class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
        <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label" for="new-client-name">Nome del client</label>
                            <input type="text" class="form-control" id="new-client-name" placeholder="es. iPhone.Mario">
                            <small class="form-hint">Lettere, numeri, . - e _</small>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Durata Certificato (giorni)</label>
                            <input type="number" class="form-control" id="new-client-cert-days" placeholder="Lascia vuoto per default istanza">
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Gruppo Firewall (opzionale)</label>
                            <select class="form-select" id="new-client-group">
                                <option value="">Nessun gruppo</option>
                            </select>
                            <small class="form-hint">Assegna il client a un gruppo firewall durante la creazione</small>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-secondary" data-bs-dismiss="modal">Annulla</button>
                        <button class="btn btn-primary" id="btn-confirm-new-client">Crea</button>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Edit Endpoint Modal -->
        <div class="modal" id="modal-edit-endpoint" tabindex="-1">
            <div class="modal-dialog modal-sm">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Modifica Endpoint</h5>
                        <button class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label" for="edit-endpoint-value">Endpoint Pubblico (IP o dominio)</label>
                            <input type="text" class="form-control" id="edit-endpoint-value" placeholder="es. vpn.example.com o 1.2.3.4">
                            <small class="form-hint">Lascia vuoto per usare auto-detect dell'IP pubblico</small>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-secondary" data-bs-dismiss="modal">Annulla</button>
                        <button class="btn btn-primary" id="btn-save-endpoint">Salva</button>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Send Email Modal -->
        <div class="modal" id="modal-send-email" tabindex="-1">
            <div class="modal-dialog modal-sm">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Invia Config via Email</h5>
                        <button class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <input type="hidden" id="send-email-client-name">
                        <div class="mb-3">
                            <label class="form-label" for="send-email-address">Email destinatario</label>
                            <input type="email" class="form-control" id="send-email-address" placeholder="utente@example.com">
                            <small class="form-hint">Il destinatario riceverà un link valido 48 ore</small>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-secondary" data-bs-dismiss="modal">Annulla</button>
                        <button class="btn btn-success" id="btn-send-email">
                            <i class="ti ti-mail me-1"></i>Invia
                        </button>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Edit Routing Modal -->
        <div class="modal" id="modal-edit-routing" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Modifica Instradamento</h5>
                        <button class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="alert alert-info">
                            <i class="ti ti-info-circle me-2"></i>
                            Le nuove rotte saranno applicate automaticamente alla prossima connessione dei client.
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Modalità Tunnel</label>
                            <div class="row g-2">
                                <div class="col-6">
                                    <input type="radio" class="btn-check" name="routing-mode" id="routing-full" value="full" ${instance.tunnel_mode === 'full' ? 'checked' : ''}>
                                    <label class="btn btn-outline-primary w-100 text-start py-2 d-block" for="routing-full">
                                        <i class="ti ti-world me-2"></i><strong>Full Tunnel</strong><br>
                                        <small class="opacity-75">Tutto il traffico passa dalla VPN</small>
                                    </label>
                                </div>
                                <div class="col-6">
                                    <input type="radio" class="btn-check" name="routing-mode" id="routing-split" value="split" ${instance.tunnel_mode === 'split' ? 'checked' : ''}>
                                    <label class="btn btn-outline-primary w-100 text-start py-2 d-block" for="routing-split">
                                        <i class="ti ti-route me-2"></i><strong>Split Tunnel</strong><br>
                                        <small class="opacity-75">Solo reti specifiche via VPN</small>
                                    </label>
                                </div>
                            </div>
                        </div>
                        <div class="mb-3" id="routing-dns-section">
                            <label class="form-label">Server DNS</label>
                            <input type="text" class="form-control" id="routing-dns" value="${(instance.dns_servers || []).join(', ')}" placeholder="es. 1.1.1.1, 8.8.8.8">
                            <small class="form-hint">Separati da virgola. Lascia vuoto per non pushare DNS ai client.</small>
                        </div>
                        <div id="routing-routes-section" class="${instance.tunnel_mode === 'full' ? 'd-none' : ''}">
                            <label class="form-label">Reti da instradare</label>
                            <div id="routing-routes-list">
                                ${(instance.routes || []).map((r, i) => `
                                    <div class="routing-route-row mb-2 d-flex gap-2 align-items-center">
                                        <input type="text" class="form-control routing-route-input" value="${r.network || r}" placeholder="es. 192.168.1.0/24" style="flex: 2">
                                        <input type="text" class="form-control routing-iface-input" value="${r.interface || ''}" placeholder="eth0" style="flex: 1" title="Interfaccia uscita (opzionale)">
                                        <button class="btn btn-outline-danger routing-remove-route" type="button"><i class="ti ti-trash"></i></button>
                                    </div>
                                `).join('')}
                            </div>
                            <button class="btn btn-sm btn-outline-primary" id="btn-add-routing-route" type="button">
                                <i class="ti ti-plus me-1"></i>Aggiungi rete
                            </button>
                            <small class="form-hint d-block mt-2">Subnet da instradare via VPN. Interfaccia opzionale per NAT (default: WAN).</small>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-secondary" data-bs-dismiss="modal">Annulla</button>
                        <button class="btn btn-primary" id="btn-save-routing">
                            <i class="ti ti-device-floppy me-1"></i>Salva e Applica
                        </button>
                    </div>
                </div>
            </div>
        </div>
        `;

        // New client button - open modal and load groups
        document.getElementById('btn-new-client')?.addEventListener('click', async () => {
            document.getElementById('new-client-name').value = '';
            document.getElementById('new-client-cert-days').value = '';

            // Load groups for dropdown
            const groupSelect = document.getElementById('new-client-group');
            groupSelect.innerHTML = '<option value="">Nessun gruppo</option>';
            try {
                const groups = await apiGet(`${MODULE_API}/instances/${currentInstanceId}/groups`);
                groups.forEach(g => {
                    groupSelect.innerHTML += `<option value="${g.id}">${escapeHtml(g.name)}</option>`;
                });
            } catch (e) {
                // Groups not available, that's OK
            }

            new bootstrap.Modal(document.getElementById('modal-new-client')).show();
        });

        // Confirm new client
        document.getElementById('btn-confirm-new-client')?.addEventListener('click', async () => {
            const name = document.getElementById('new-client-name').value.trim();
            const certDays = document.getElementById('new-client-cert-days').value;
            const groupId = document.getElementById('new-client-group').value || null;
            if (!name) {
                showToast('Inserisci un nome per il client', 'error');
                return;
            }
            try {
                await apiPost(`${MODULE_API}/instances/${currentInstanceId}/clients`, {
                    name,
                    cert_duration_days: certDays ? parseInt(certDays) : null,
                    group_id: groupId
                });
                showToast('Client creato con successo', 'success');
                bootstrap.Modal.getInstance(document.getElementById('modal-new-client'))?.hide();
                renderInstanceDetail(container);
            } catch (err) {
                showToast(err.message, 'error');
            }
        });

        // Edit endpoint button
        document.getElementById('btn-edit-endpoint')?.addEventListener('click', () => {
            document.getElementById('edit-endpoint-value').value = instance.endpoint || '';
            new bootstrap.Modal(document.getElementById('modal-edit-endpoint')).show();
        });

        // Save endpoint
        document.getElementById('btn-save-endpoint')?.addEventListener('click', async () => {
            const endpoint = document.getElementById('edit-endpoint-value').value.trim() || null;
            try {
                await apiPatch(`${MODULE_API}/instances/${currentInstanceId}`, { endpoint });
                showToast('Endpoint aggiornato', 'success');
                bootstrap.Modal.getInstance(document.getElementById('modal-edit-endpoint'))?.hide();
                document.getElementById('display-endpoint').textContent = endpoint || '(auto-detect)';
                instance.endpoint = endpoint;
            } catch (err) {
                showToast(err.message, 'error');
            }
        });

        // Edit routing button
        document.getElementById('btn-edit-routing')?.addEventListener('click', async () => {
            new bootstrap.Modal(document.getElementById('modal-edit-routing')).show();
        });

        // Toggle routes section visibility based on mode selection
        document.querySelectorAll('input[name="routing-mode"]').forEach(radio => {
            radio.addEventListener('change', () => {
                const routesSection = document.getElementById('routing-routes-section');
                if (document.getElementById('routing-split').checked) {
                    routesSection.classList.remove('d-none');
                } else {
                    routesSection.classList.add('d-none');
                }
            });
        });

        // Add route button
        document.getElementById('btn-add-routing-route')?.addEventListener('click', () => {
            const list = document.getElementById('routing-routes-list');
            const row = document.createElement('div');
            row.className = 'routing-route-row mb-2 d-flex gap-2 align-items-center';
            row.innerHTML = `
                <input type="text" class="form-control routing-route-input" placeholder="es. 192.168.1.0/24" style="flex: 2">
                <input type="text" class="form-control routing-iface-input" placeholder="eth0" style="flex: 1" title="Interfaccia uscita (opzionale)">
                <button class="btn btn-outline-danger routing-remove-route" type="button"><i class="ti ti-trash"></i></button>
            `;
            list.appendChild(row);
        });

        // Remove route buttons (event delegation)
        document.getElementById('routing-routes-list')?.addEventListener('click', (e) => {
            if (e.target.closest('.routing-remove-route')) {
                e.target.closest('.routing-route-row')?.remove();
            }
        });

        // Save routing
        document.getElementById('btn-save-routing')?.addEventListener('click', async () => {
            const btn = document.getElementById('btn-save-routing');
            const originalHtml = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Salvataggio...';

            try {
                const tunnelMode = document.querySelector('input[name="routing-mode"]:checked').value;
                let routes = [];

                // Parse DNS servers
                const dnsInput = document.getElementById('routing-dns').value.trim();
                const dnsServers = dnsInput ? dnsInput.split(',').map(s => s.trim()).filter(s => s) : [];

                if (tunnelMode === 'split') {
                    document.querySelectorAll('.routing-route-row').forEach(row => {
                        const networkInput = row.querySelector('.routing-route-input');
                        const ifaceInput = row.querySelector('.routing-iface-input');
                        const network = networkInput?.value.trim();
                        const iface = ifaceInput?.value.trim();
                        if (network) {
                            routes.push({ network: network, interface: iface || null });
                        }
                    });
                    if (routes.length === 0) {
                        showToast('Split tunnel richiede almeno una rete', 'error');
                        btn.disabled = false;
                        btn.innerHTML = originalHtml;
                        return;
                    }
                }

                const result = await apiPatch(`${MODULE_API}/instances/${currentInstanceId}/routing`, {
                    tunnel_mode: tunnelMode,
                    routes: routes,
                    dns_servers: dnsServers
                });

                bootstrap.Modal.getInstance(document.getElementById('modal-edit-routing'))?.hide();
                showToast(result.message, 'success');

                if (result.warning) {
                    setTimeout(() => showToast(result.warning, 'warning'), 1500);
                }

                // Reload to show updated data
                renderInstanceDetail(container);
            } catch (err) {
                showToast(err.message, 'error');
            } finally {
                btn.disabled = false;
                btn.innerHTML = originalHtml;
            }
        });

        // Load PKI tab when clicked
        document.getElementById('tab-pki')?.addEventListener('shown.bs.tab', async () => {
            await loadPKIStatus();
        });

        // Load firewall tab when clicked
        document.getElementById('tab-firewall')?.addEventListener('shown.bs.tab', async () => {
            try {
                const firewallModule = await import('./firewall.js');
                await firewallModule.init(document.getElementById('firewall-content'), currentInstanceId);
            } catch (err) {
                document.getElementById('firewall-content').innerHTML = `
                    <div class="alert alert-danger">${err.message}</div>
                `;
            }
        });
    } catch (err) {
        container.innerHTML = `<div class="alert alert-danger">
            <i class="ti ti-alert-circle me-2"></i>${err.message}
        </div>`;
    }
}

// Render certificate status badge
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

// Load PKI status
async function loadPKIStatus() {
    const container = document.getElementById('pki-content');
    try {
        const [instance, pkiStatus] = await Promise.all([
            apiGet(`${MODULE_API}/instances/${currentInstanceId}`),
            apiGet(`${MODULE_API}/instances/${currentInstanceId}/pki/status`)
        ]);

        container.innerHTML = `
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
                                        ${instance.server_cert_expiry ? new Date(instance.server_cert_expiry).toLocaleDateString('it-IT') : 'N/A'}
                                    </div>
                                </div>
                                <div class="datagrid-item">
                                    <div class="datagrid-title">Giorni Rimanenti</div>
                                    <div class="datagrid-content">
                                        ${renderCertStatus(pkiStatus.server_cert_days_remaining, false)}
                                    </div>
                                </div>
                            </div>
                            ${canManage ? `
                            <button class="btn btn-warning mt-3" onclick="renewServerCert()">
                                <i class="ti ti-refresh me-1"></i>Rinnova Certificato Server
                            </button>` : ''}
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
                                        ${pkiStatus.ca_expiry ? new Date(pkiStatus.ca_expiry).toLocaleDateString('it-IT') : 'N/A'}
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
    } catch (err) {
        container.innerHTML = `<div class="alert alert-danger">${err.message}</div>`;
    }
}

// ============== GLOBAL FUNCTIONS ==============

window.startInstance = async (id) => {
    try {
        await apiPost(`${MODULE_API}/instances/${id}/start`);
        showToast('Istanza avviata', 'success');
        location.reload();
    } catch (err) {
        showToast(err.message, 'error');
    }
};

window.stopInstance = async (id) => {
    try {
        await apiPost(`${MODULE_API}/instances/${id}/stop`);
        showToast('Istanza fermata', 'success');
        location.reload();
    } catch (err) {
        showToast(err.message, 'error');
    }
};

window.deleteInstance = async (id) => {
    if (await confirmDialog('Eliminare questa istanza e tutti i suoi client?', 'Elimina')) {
        try {
            await apiDelete(`${MODULE_API}/instances/${id}`);
            showToast('Istanza eliminata', 'success');
            location.href = '#openvpn';
        } catch (err) {
            showToast(err.message, 'error');
        }
    }
};

window.downloadConfig = async (name) => {
    try {
        const token = localStorage.getItem('madmin_token');
        const res = await fetch(`/api${MODULE_API}/instances/${currentInstanceId}/clients/${name}/config`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!res.ok) throw new Error('Download fallito: ' + res.statusText);

        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${name}.ovpn`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
    } catch (err) {
        showToast(err.message, 'error');
    }
};

window.showQR = async (name) => {
    try {
        const token = localStorage.getItem('madmin_token');
        const res = await fetch(`/api${MODULE_API}/instances/${currentInstanceId}/clients/${name}/qr`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!res.ok) throw new Error('Caricamento QR fallito: ' + res.statusText);

        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);

        const modal = document.createElement('div');
        modal.innerHTML = `
            <div class="modal fade" tabindex="-1">
                <div class="modal-dialog modal-sm">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">QR Code - ${escapeHtml(name)}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body text-center p-4">
                            <img src="${url}" class="img-fluid" alt="QR Code">
                            <p class="mt-3 mb-0 text-muted small">Il QR contiene un link per scaricare la configurazione (valido 48 ore)</p>
                        </div>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
        const bsModal = new bootstrap.Modal(modal.querySelector('.modal'));
        bsModal.show();
        modal.querySelector('.modal').addEventListener('hidden.bs.modal', () => {
            modal.remove();
            window.URL.revokeObjectURL(url);
        });
    } catch (err) {
        showToast(err.message, 'error');
    }
};

window.revokeClient = async (name) => {
    if (await confirmDialog('Revoca Client', `Revocare il client "${name}"? Il client perderà l'accesso alla VPN.`, 'Revoca')) {
        try {
            await apiDelete(`${MODULE_API}/instances/${currentInstanceId}/clients/${name}`);
            showToast('Client revocato', 'success');
            location.reload();
        } catch (err) {
            showToast(err.message, 'error');
        }
    }
};

window.renewClientCert = async (name) => {
    if (await confirmDialog('Rinnova Certificato', `Rinnovare il certificato per "${name}"? Il client dovrà riscaricare la configurazione.`, 'Rinnova')) {
        try {
            await apiPost(`${MODULE_API}/instances/${currentInstanceId}/clients/${name}/renew`);
            showToast('Certificato rinnovato', 'success');
            location.reload();
        } catch (err) {
            showToast(err.message, 'error');
        }
    }
};

window.restoreClient = async (name) => {
    if (await confirmDialog('Ripristina Client', `Ripristinare il client "${name}"? Verrà generato un nuovo certificato e il client dovrà scaricare la nuova configurazione.`, 'Ripristina', 'btn-success')) {
        try {
            await apiPost(`${MODULE_API}/instances/${currentInstanceId}/clients/${name}/restore`);
            showToast('Client ripristinato con nuovo certificato', 'success');
            location.reload();
        } catch (err) {
            showToast(err.message, 'error');
        }
    }
};

window.deleteClientPermanent = async (name) => {
    if (await confirmDialog('Elimina Client', `Eliminare definitivamente il client "${name}"? Questa azione è irreversibile.`, 'Elimina')) {
        try {
            await apiDelete(`${MODULE_API}/instances/${currentInstanceId}/clients/${name}/permanent`);
            showToast('Client eliminato definitivamente', 'success');
            location.reload();
        } catch (err) {
            showToast(err.message, 'error');
        }
    }
};

window.renewServerCert = async () => {
    if (await confirmDialog('Rinnova Certificato Server', 'Rinnovare il certificato server? L\'istanza verrà riavviata.', 'Rinnova')) {
        try {
            await apiPost(`${MODULE_API}/instances/${currentInstanceId}/pki/renew-server`);
            showToast('Certificato server rinnovato', 'success');
            location.reload();
        } catch (err) {
            showToast(err.message, 'error');
        }
    }
};

window.openSendEmailModal = (clientName) => {
    document.getElementById('send-email-client-name').value = clientName;
    document.getElementById('send-email-address').value = '';
    new bootstrap.Modal(document.getElementById('modal-send-email')).show();
};

// Setup send email button handler
document.addEventListener('click', async (e) => {
    if (e.target.id === 'btn-send-email' || e.target.closest('#btn-send-email')) {
        const clientName = document.getElementById('send-email-client-name').value;
        const email = document.getElementById('send-email-address').value.trim();

        if (!email) {
            showToast('Inserisci un indirizzo email', 'error');
            return;
        }

        const btn = document.getElementById('btn-send-email');
        const originalHtml = btn.innerHTML;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Invio...';
        btn.disabled = true;

        try {
            await apiPost(`${MODULE_API}/instances/${currentInstanceId}/clients/${clientName}/send-config`, { email });
            showToast(`Email inviata a ${email}`, 'success');
            bootstrap.Modal.getInstance(document.getElementById('modal-send-email'))?.hide();
        } catch (err) {
            showToast(err.message, 'error');
        } finally {
            btn.innerHTML = originalHtml;
            btn.disabled = false;
        }
    }
});
