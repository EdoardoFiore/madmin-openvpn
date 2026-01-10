/**
 * OpenVPN Module - Firewall View
 * 
 * Manages client groups and firewall rules for OpenVPN instances.
 * Layout matches WireGuard firewall module for consistency.
 */

import { apiGet, apiPost, apiPatch, apiDelete, apiPut } from '/static/js/api.js';
import { showToast, confirmDialog, loadingSpinner } from '/static/js/utils.js';
import { checkPermission } from '/static/js/app.js';

const MODULE_API = '/modules/openvpn';

let currentInstanceId = null;
let currentGroupId = null;
let groups = [];
let clients = [];
let instance = null;  // Current instance data including firewall_default_policy
let canManageGroups = false;  // openvpn.groups permission

/**
 * Initialize the firewall view for an instance
 */
export async function init(container, instanceId) {
    currentInstanceId = instanceId;
    canManageGroups = checkPermission('openvpn.groups');
    container.innerHTML = loadingSpinner();

    try {
        // Load instance, groups, and clients
        [instance, groups, clients] = await Promise.all([
            apiGet(`${MODULE_API}/instances/${instanceId}`),
            apiGet(`${MODULE_API}/instances/${instanceId}/groups`),
            apiGet(`${MODULE_API}/instances/${instanceId}/clients`)
        ]);

        // Auto-select first group if available
        if (groups.length > 0 && !currentGroupId) {
            currentGroupId = groups[0].id;
        }

        render(container);

        // Load group details if a group is selected
        if (currentGroupId) {
            loadGroupDetails();
        }
    } catch (err) {
        container.innerHTML = `<div class="alert alert-danger">${err.message}</div>`;
    }
}

function render(container) {
    container.innerHTML = `
        <!-- Instance Default Policy -->
        <div class="card mb-3">
            <div class="card-body py-2 d-flex align-items-center gap-3">
                <strong>Default Policy</strong>
                ${canManageGroups ? `
                <div class="btn-group" role="group">
                    <input type="radio" class="btn-check" name="default-policy" id="policy-accept" value="ACCEPT" 
                           ${instance?.firewall_default_policy !== 'DROP' ? 'checked' : ''}>
                    <label class="btn btn-outline-success btn-sm" for="policy-accept">ACCEPT</label>
                    <input type="radio" class="btn-check" name="default-policy" id="policy-drop" value="DROP"
                           ${instance?.firewall_default_policy === 'DROP' ? 'checked' : ''}>
                    <label class="btn btn-outline-danger btn-sm" for="policy-drop">DROP</label>
                </div>` : `
                <span class="badge ${instance?.firewall_default_policy === 'DROP' ? 'bg-danger' : 'bg-success'} fs-6">
                    ${instance?.firewall_default_policy || 'ACCEPT'}
                </span>`}
            </div>
        </div>
        
        <div class="row">
            <!-- Groups List -->
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h4 class="card-title mb-0">Gruppi</h4>
                        ${canManageGroups ? `
                        <button class="btn btn-sm btn-primary" id="btn-new-group">
                            <i class="ti ti-plus me-1"></i>Nuovo
                        </button>` : ''}
                    </div>
                    <div class="list-group list-group-flush" id="groups-list">
                        ${renderGroupsList()}
                    </div>
                </div>
            </div>
            
            <!-- Group Details -->
            <div class="col-md-8">
                <div id="group-details">
                    ${currentGroupId ? renderGroupDetails() : renderNoGroupSelected()}
                </div>
            </div>
        </div>
        
        <!-- Create Group Modal -->
        <div class="modal fade" id="modal-new-group" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Nuovo Gruppo</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label">Nome</label>
                            <input type="text" class="form-control" id="new-group-name" placeholder="Amministratori">
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Descrizione</label>
                            <input type="text" class="form-control" id="new-group-desc" placeholder="Opzionale">
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-secondary" data-bs-dismiss="modal">Annulla</button>
                        <button class="btn btn-primary" id="btn-create-group">Crea</button>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Add Member Modal -->
        <div class="modal fade" id="modal-add-member" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Aggiungi Membro</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <select class="form-select" id="member-client-select">
                            <option value="">Seleziona client...</option>
                            ${clients.filter(c => !c.revoked).map(c => `<option value="${c.id}">${c.name} (${c.allocated_ip})</option>`).join('')}
                        </select>
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-secondary" data-bs-dismiss="modal">Annulla</button>
                        <button class="btn btn-primary" id="btn-confirm-add-member">Aggiungi</button>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Add Rule Modal -->
        <div class="modal fade" id="modal-add-rule" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Nuova Regola</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="row mb-3">
                            <div class="col-6">
                                <label class="form-label">Azione</label>
                                <select class="form-select" id="rule-action">
                                    <option value="ACCEPT">ACCEPT</option>
                                    <option value="DROP">DROP</option>
                                </select>
                            </div>
                            <div class="col-6">
                                <label class="form-label">Protocollo</label>
                                <select class="form-select" id="rule-protocol">
                                    <option value="all">Tutti</option>
                                    <option value="tcp">TCP</option>
                                    <option value="udp">UDP</option>
                                    <option value="icmp">ICMP</option>
                                </select>
                            </div>
                        </div>
                        <div class="row mb-3">
                            <div class="col-8">
                                <label class="form-label">Destinazione</label>
                                <input type="text" class="form-control" id="rule-destination" placeholder="0.0.0.0/0">
                            </div>
                            <div class="col-4" id="port-field-container">
                                <label class="form-label">Porta</label>
                                <input type="text" class="form-control" id="rule-port" placeholder="80">
                            </div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Descrizione</label>
                            <input type="text" class="form-control" id="rule-description" placeholder="Opzionale">
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-secondary" data-bs-dismiss="modal">Annulla</button>
                        <button class="btn btn-primary" id="btn-create-rule">Crea</button>
                    </div>
                </div>
            </div>
        </div>
    `;

    setupEventHandlers(container);
}

function renderGroupsList() {
    if (groups.length === 0) {
        return '<div class="list-group-item text-muted text-center py-3">Nessun gruppo</div>';
    }

    return groups.map(g => `
        <a href="#" class="list-group-item list-group-item-action ${g.id === currentGroupId ? 'active' : ''}"
           data-group-id="${g.id}">
            <div class="d-flex justify-content-between align-items-center">
                <div>
                    <strong>${g.name}</strong>
                    <small class="d-block ${g.id === currentGroupId ? 'text-white-50' : 'text-muted'}">${g.description || 'Nessuna descrizione'}</small>
                </div>
                <div class="d-flex gap-1">
                    <span class="badge bg-blue-lt text-blue">${g.member_count} <i class="ti ti-users"></i></span>
                    <span class="badge bg-green-lt text-green">${g.rule_count} <i class="ti ti-shield"></i></span>
                </div>
            </div>
        </a>
    `).join('');
}

function renderNoGroupSelected() {
    return `
        <div class="card">
            <div class="card-body text-center py-5 text-muted">
                <i class="ti ti-users-group" style="font-size: 3rem;"></i>
                <p class="mt-3 mb-0">Seleziona un gruppo per gestirne membri e regole</p>
            </div>
        </div>
    `;
}

function renderGroupDetails() {
    const group = groups.find(g => g.id === currentGroupId);
    if (!group) return renderNoGroupSelected();

    return `
        <div class="card mb-3">
            <div class="card-header d-flex justify-content-between align-items-center">
                <div>
                    <h4 class="card-title mb-0">${group.name}</h4>
                    <small class="text-muted">${group.description || ''}</small>
                </div>
                ${canManageGroups ? `
                <button class="btn btn-sm btn-outline-danger" id="btn-delete-group">
                    <i class="ti ti-trash"></i>
                </button>` : ''}
            </div>
        </div>
        
        <!-- Members -->
        <div class="card mb-3">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="card-title mb-0"><i class="ti ti-users me-2"></i>Membri</h5>
                ${canManageGroups ? `
                <button class="btn btn-sm btn-primary" id="btn-show-add-member">
                    <i class="ti ti-user-plus me-1"></i>Aggiungi
                </button>` : ''}
            </div>
            <div class="card-body" id="members-container">${loadingSpinner()}</div>
        </div>
        
        <!-- Rules -->
        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="card-title mb-0"><i class="ti ti-shield me-2"></i>Regole Firewall</h5>
                ${canManageGroups ? `
                <button class="btn btn-sm btn-primary" id="btn-add-rule">
                    <i class="ti ti-plus me-1"></i>Nuova Regola
                </button>` : ''}
            </div>
            <div class="card-body" id="rules-container">${loadingSpinner()}</div>
        </div>
    `;
}

async function loadGroupDetails() {
    if (!currentGroupId) return;

    try {
        const [members, rules] = await Promise.all([
            apiGet(`${MODULE_API}/instances/${currentInstanceId}/groups/${currentGroupId}/members`),
            apiGet(`${MODULE_API}/instances/${currentInstanceId}/groups/${currentGroupId}/rules`)
        ]);

        renderMembers(members);
        renderRules(rules);
    } catch (err) {
        showToast(err.message, 'error');
    }
}

function renderMembers(members) {
    const container = document.getElementById('members-container');
    if (!container) return;

    if (members.length === 0) {
        container.innerHTML = '<p class="text-muted mb-0">Nessun membro nel gruppo</p>';
        return;
    }

    container.innerHTML = `
        <div class="d-flex flex-wrap gap-2">
            ${members.map(m => `
                <span class="badge bg-primary-lt d-inline-flex align-items-center gap-2">
                    ${m.client_name} <small class="opacity-75">(${m.client_ip})</small>
                    ${canManageGroups ? `
                    <button class="btn btn-ghost-danger btn-sm p-0" onclick="removeMember('${m.client_id}')">
                        <i class="ti ti-x"></i>
                    </button>` : ''}
                </span>
            `).join('')}
        </div>
    `;
}

function renderRules(rules) {
    const container = document.getElementById('rules-container');
    if (!container) return;

    if (rules.length === 0) {
        container.innerHTML = '<p class="text-muted mb-0">Nessuna regola definita. Verrà usata la policy di default.</p>';
        return;
    }

    container.innerHTML = `
        <table class="table table-vcenter table-sm">
            <thead>
                <tr>
                    ${canManageGroups ? '<th style="width: 30px"></th>' : ''}
                    <th style="width: 40px">#</th>
                    <th>Azione</th>
                    <th>Proto</th>
                    <th>Destinazione</th>
                    <th>Porta</th>
                    <th>Note</th>
                    ${canManageGroups ? '<th class="w-1"></th>' : ''}
                </tr>
            </thead>
            <tbody id="rules-tbody">
                ${rules.map((r, i) => `
                    <tr data-rule-id="${r.id}" data-order="${r.order}">
                        ${canManageGroups ? '<td class="cursor-move text-muted" style="cursor: grab;"><i class="ti ti-grip-vertical"></i></td>' : ''}
                        <td class="text-muted">${i + 1}</td>
                        <td><span class="badge ${r.action === 'ACCEPT' ? 'bg-success' : 'bg-danger'}">${r.action}</span></td>
                        <td><code>${r.protocol}</code></td>
                        <td><code>${r.destination}</code></td>
                        <td>${r.port || '*'}</td>
                        <td class="text-muted">${r.description || ''}</td>
                        ${canManageGroups ? `
                        <td>
                            <div class="btn-group btn-group-sm">
                                <button class="btn btn-ghost-primary" onclick="editRule('${r.id}')">
                                    <i class="ti ti-pencil"></i>
                                </button>
                                <button class="btn btn-ghost-danger" onclick="deleteRule('${r.id}')">
                                    <i class="ti ti-trash"></i>
                                </button>
                            </div>
                        </td>` : ''}
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;

    // Initialize drag-drop sorting
    initRuleSorting();
}

function setupEventHandlers(container) {
    // Group selection
    container.querySelectorAll('[data-group-id]').forEach(el => {
        el.addEventListener('click', (e) => {
            e.preventDefault();
            currentGroupId = e.currentTarget.dataset.groupId;
            render(container);
            loadGroupDetails();
        });
    });

    // New group button
    document.getElementById('btn-new-group')?.addEventListener('click', () => {
        new bootstrap.Modal(document.getElementById('modal-new-group')).show();
    });

    // Create group
    document.getElementById('btn-create-group')?.addEventListener('click', async () => {
        const name = document.getElementById('new-group-name').value.trim();
        const description = document.getElementById('new-group-desc').value.trim();

        if (!name) {
            showToast('Inserisci un nome', 'error');
            return;
        }

        try {
            await apiPost(`${MODULE_API}/instances/${currentInstanceId}/groups`, { name, description });
            showToast('Gruppo creato', 'success');
            bootstrap.Modal.getInstance(document.getElementById('modal-new-group'))?.hide();

            groups = await apiGet(`${MODULE_API}/instances/${currentInstanceId}/groups`);
            render(container);
        } catch (err) {
            showToast(err.message, 'error');
        }
    });

    // Delete group
    document.getElementById('btn-delete-group')?.addEventListener('click', async () => {
        if (await confirmDialog('Elimina Gruppo', 'Eliminare questo gruppo e tutte le sue regole?', 'Elimina')) {
            try {
                await apiDelete(`${MODULE_API}/instances/${currentInstanceId}/groups/${currentGroupId}`);
                showToast('Gruppo eliminato', 'success');
                currentGroupId = null;
                groups = await apiGet(`${MODULE_API}/instances/${currentInstanceId}/groups`);
                render(container);
            } catch (err) {
                showToast(err.message, 'error');
            }
        }
    });

    // Show add member modal
    document.getElementById('btn-show-add-member')?.addEventListener('click', () => {
        new bootstrap.Modal(document.getElementById('modal-add-member')).show();
    });

    // Confirm add member (in modal)
    document.getElementById('btn-confirm-add-member')?.addEventListener('click', async () => {
        const clientId = document.getElementById('member-client-select').value;
        if (!clientId) {
            showToast('Seleziona un client', 'error');
            return;
        }

        try {
            await apiPost(`${MODULE_API}/instances/${currentInstanceId}/groups/${currentGroupId}/members?client_id=${clientId}`);
            showToast('Membro aggiunto', 'success');
            bootstrap.Modal.getInstance(document.getElementById('modal-add-member'))?.hide();
            loadGroupDetails();
        } catch (err) {
            showToast(err.message, 'error');
        }
    });

    // Add rule button
    document.getElementById('btn-add-rule')?.addEventListener('click', () => {
        // Reset port field visibility
        document.getElementById('port-field-container').style.display = 'block';
        document.getElementById('rule-protocol').value = 'all';
        document.getElementById('port-field-container').style.display = 'none';
        new bootstrap.Modal(document.getElementById('modal-add-rule')).show();
    });

    // Protocol change - toggle port field visibility
    document.getElementById('rule-protocol')?.addEventListener('change', (e) => {
        const portContainer = document.getElementById('port-field-container');
        if (e.target.value === 'all' || e.target.value === 'icmp') {
            portContainer.style.display = 'none';
            document.getElementById('rule-port').value = '';
        } else {
            portContainer.style.display = 'block';
        }
    });

    // Create/Edit rule
    document.getElementById('btn-create-rule')?.addEventListener('click', async () => {
        const modal = document.getElementById('modal-add-rule');
        const editRuleId = modal?.dataset.editRuleId;
        const protocol = document.getElementById('rule-protocol').value;
        const data = {
            action: document.getElementById('rule-action').value,
            protocol: protocol,
            destination: document.getElementById('rule-destination').value.trim() || '0.0.0.0/0',
            port: (protocol === 'tcp' || protocol === 'udp') ? (document.getElementById('rule-port').value.trim() || null) : null,
            description: document.getElementById('rule-description').value.trim()
        };

        try {
            if (editRuleId) {
                // Edit existing rule
                await apiPatch(`${MODULE_API}/instances/${currentInstanceId}/groups/${currentGroupId}/rules/${editRuleId}`, data);
                showToast('Regola aggiornata', 'success');
            } else {
                // Create new rule
                await apiPost(`${MODULE_API}/instances/${currentInstanceId}/groups/${currentGroupId}/rules`, data);
                showToast('Regola creata', 'success');
            }
            bootstrap.Modal.getInstance(modal)?.hide();
            loadGroupDetails();
            refreshGroupsList();
        } catch (err) {
            showToast(err.message, 'error');
        }
    });

    // Reset modal when closed
    document.getElementById('modal-add-rule')?.addEventListener('hidden.bs.modal', () => {
        const modal = document.getElementById('modal-add-rule');
        delete modal.dataset.editRuleId;
        modal.querySelector('.modal-title').textContent = 'Nuova Regola';
        document.getElementById('btn-create-rule').textContent = 'Crea';
        // Reset form
        document.getElementById('rule-action').value = 'DROP';
        document.getElementById('rule-protocol').value = 'all';
        document.getElementById('rule-destination').value = '';
        document.getElementById('rule-port').value = '';
        document.getElementById('rule-description').value = '';
        document.getElementById('port-field-container').style.display = 'none';
    });
}

// Global functions for inline handlers
window.removeMember = async (clientId) => {
    if (await confirmDialog('Rimuovi Membro', 'Rimuovere questo membro dal gruppo?', 'Rimuovi')) {
        try {
            await apiDelete(`${MODULE_API}/instances/${currentInstanceId}/groups/${currentGroupId}/members/${clientId}`);
            showToast('Membro rimosso', 'success');
            loadGroupDetails();
            refreshGroupsList();
        } catch (err) {
            showToast(err.message, 'error');
        }
    }
};

window.deleteRule = async (ruleId) => {
    if (await confirmDialog('Elimina Regola', 'Eliminare questa regola?', 'Elimina')) {
        try {
            await apiDelete(`${MODULE_API}/instances/${currentInstanceId}/groups/${currentGroupId}/rules/${ruleId}`);
            showToast('Regola eliminata', 'success');
            loadGroupDetails();
            refreshGroupsList();
        } catch (err) {
            showToast(err.message, 'error');
        }
    }
};

window.editRule = async (ruleId) => {
    // Find rule data
    const rulesData = await apiGet(`${MODULE_API}/instances/${currentInstanceId}/groups/${currentGroupId}/rules`);
    const rule = rulesData.find(r => r.id === ruleId);
    if (!rule) return;

    // Populate modal fields
    document.getElementById('rule-action').value = rule.action;
    document.getElementById('rule-protocol').value = rule.protocol;
    document.getElementById('rule-destination').value = rule.destination || '';
    document.getElementById('rule-port').value = rule.port || '';
    document.getElementById('rule-description').value = rule.description || '';

    // Show/hide port field based on protocol
    const portContainer = document.getElementById('port-field-container');
    if (portContainer) {
        portContainer.style.display = (rule.protocol === 'tcp' || rule.protocol === 'udp') ? '' : 'none';
    }

    // Mark as editing
    const modal = document.getElementById('modal-add-rule');
    modal.dataset.editRuleId = ruleId;
    modal.querySelector('.modal-title').textContent = 'Modifica Regola';
    document.getElementById('btn-create-rule').textContent = 'Salva';

    new bootstrap.Modal(modal).show();
};

// Refresh groups list (updates member/rule counts)
async function refreshGroupsList() {
    try {
        groups = await apiGet(`${MODULE_API}/instances/${currentInstanceId}/groups`);
        const listEl = document.getElementById('groups-list');
        if (listEl) {
            listEl.innerHTML = renderGroupsList();
            // Re-attach click handlers
            listEl.querySelectorAll('[data-group-id]').forEach(el => {
                el.addEventListener('click', (e) => {
                    e.preventDefault();
                    currentGroupId = e.currentTarget.dataset.groupId;
                    document.querySelectorAll('[data-group-id]').forEach(g => g.classList.remove('active'));
                    e.currentTarget.classList.add('active');
                    loadGroupDetails();
                });
            });
        }
    } catch (err) {
        console.error('Failed to refresh groups list:', err);
    }
}

// Initialize drag-drop sorting for rules
function initRuleSorting() {
    const tbody = document.getElementById('rules-tbody');
    if (!tbody || typeof Sortable === 'undefined') return;

    new Sortable(tbody, {
        animation: 150,
        handle: 'td.cursor-move',
        ghostClass: 'table-active',
        onEnd: async function (evt) {
            // Collect new order
            const rows = tbody.querySelectorAll('tr[data-rule-id]');
            const orders = [];
            rows.forEach((row, index) => {
                orders.push({
                    id: row.dataset.ruleId,
                    order: index
                });
            });

            // Update order numbers in UI
            rows.forEach((row, index) => {
                row.querySelector('td:nth-child(2)').textContent = index + 1;
            });

            // Save to API
            try {
                await apiPut(`${MODULE_API}/instances/${currentInstanceId}/groups/${currentGroupId}/rules/order`, orders);
                showToast('Ordine aggiornato', 'success');
            } catch (err) {
                showToast(err.message, 'error');
                loadGroupDetails(); // Reload on error
            }
        }
    });
}

// Handle policy change
document.addEventListener('change', async (e) => {
    if (e.target.name === 'default-policy') {
        const newPolicy = e.target.value;
        try {
            await apiPatch(`${MODULE_API}/instances/${currentInstanceId}/firewall-policy`, { policy: newPolicy });
            instance.firewall_default_policy = newPolicy;
            showToast(`Policy aggiornata a ${newPolicy}`, 'success');
        } catch (err) {
            showToast(err.message, 'error');
        }
    }
});

// Add CSS for cursor
const style = document.createElement('style');
style.textContent = '.cursor-move { cursor: move; }';
document.head.appendChild(style);
