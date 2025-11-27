import { state } from './modules/state.js';
import { getCookie, showToast } from './modules/utils.js';
import { GraphManager } from './modules/graph.js';
import { ExplorerManager } from './modules/explorer.js';

const app = {
    init: async () => {
        try {
            app.compilePatterns();

            const res = await fetch(window.HuntsmanConfig.urls.services);
            if (!res.ok) throw new Error("API Error");
            state.services = await res.json();
            app.renderServices();
            app.renderManualTypes();
            
            const pivotModalEl = document.getElementById('pivotModal');
            if (pivotModalEl) {
                state.pivotModal = new bootstrap.Modal(pivotModalEl, { backdrop: false });
            }

            const addObjectModalEl = document.getElementById('addObjectModal');
            if (addObjectModalEl) {
                state.addObjectModal = new bootstrap.Modal(addObjectModalEl);
            }

            const relModalEl = document.getElementById('relationshipModal');
            if (relModalEl) {
                state.relationshipModal = new bootstrap.Modal(relModalEl);
            }

            const inputEl = document.getElementById('input-text');
            if (inputEl) {
                inputEl.addEventListener('input', (e) => {
                    const iocs = app.extractIOCs(e.target.value);
                    const countBadge = document.getElementById('ioc-count');
                    if(countBadge) countBadge.innerHTML = `<i class="bi bi-crosshair me-1"></i>${iocs.length} artifacts detected`;
                });
            }

            const manualId = document.getElementById('manual-id');
            const manualType = document.getElementById('manual-type');
            if (manualId && manualType) {
                const triggerAdd = (e) => {
                    if (e.key === 'Enter') app.addManualIOC();
                };
                manualId.addEventListener('keydown', triggerAdd);
                manualType.addEventListener('keydown', triggerAdd);
            }

            const searchEl = document.getElementById('service-search');
            if (searchEl) {
                searchEl.addEventListener('input', (e) => app.filterServices(e.target.value));
            }

            state.manualIocs = [];
            state.connectionSource = null;

            ExplorerManager.initSuperDB();

            const runBtn = document.getElementById('btn-run-zq');
            if(runBtn) runBtn.addEventListener('click', app.runExplorerQuery);

        } catch (err) {
            console.error(err);
        }
    },

    toggleInputView: (mode) => {
        const regexCard = document.getElementById('mode-regex');
        const manualCard = document.getElementById('mode-manual');
        const tabRegex = document.getElementById('tab-regex');
        const tabManual = document.getElementById('tab-manual');

        if (mode === 'regex') {
            regexCard.classList.remove('d-none');
            manualCard.classList.add('d-none');
            tabRegex.classList.add('active');
            tabManual.classList.remove('active');
        } else {
            regexCard.classList.add('d-none');
            manualCard.classList.remove('d-none');
            tabRegex.classList.remove('active');
            tabManual.classList.add('active');
        }
    },

    compilePatterns: () => {
        if (window.HuntsmanConfig && window.HuntsmanConfig.patterns) {
            for (const [key, patternStr] of Object.entries(window.HuntsmanConfig.patterns)) {
                try {
                    state.patterns[key] = new RegExp(patternStr, 'gi');
                } catch (e) {
                    console.error(e);
                }
            }
        }
    },

    extractIOCs: (text) => {
        if (!text) return [];
        const results = [];
        const seen = new Set();
        for (const [type, regex] of Object.entries(state.patterns)) {
            const matches = text.match(regex);
            if (matches) {
                matches.forEach(match => {
                    const clean = match.trim();
                    const key = `${type}:${clean}`;
                    if (!seen.has(key)) {
                        results.push({ value: clean, type: type });
                        seen.add(key);
                    }
                });
            }
        }
        return results;
    },

    renderServices: () => {
        const container = document.getElementById('services-container');
        if (!container) return;
        if (state.services.length === 0) {
            container.innerHTML = '<div class="p-3 text-center text-muted">No services available.</div>';
            return;
        }
        container.innerHTML = state.services.map(service => `
            <div class="service-item p-2 d-flex align-items-center justify-content-between border-bottom" 
                 onclick="app.toggleService('${service.name}')" 
                 id="row-${service.name}"
                 data-label="${service.label.toLowerCase()}"
                 data-name="${service.name.toLowerCase()}"
                 data-types="${(service.supported_types || []).join(',').toLowerCase()}">
                <div class="form-check m-0">
                    <input class="form-check-input pointer-events-none" type="checkbox" value="${service.name}" id="chk-${service.name}">
                    <label class="form-check-label fw-bold text-capitalize ms-2 pointer-events-none" style="font-size: 0.85rem;">${service.label}</label>
                </div>
                <div class="d-flex flex-wrap gap-1 justify-content-end" style="max-width: 40%;">
                    ${service.supported_types.map(t => `<span class="badge bg-light text-dark border" style="font-size: 0.6rem;">${t}</span>`).join('')}
                </div>
            </div>
        `).join('');
    },

    renderManualTypes: () => {
        const datalist = document.getElementById('ioc-types');
        if (!datalist) return;
        
        const types = new Set();

        if (state.services) {
            state.services.forEach(s => {
                if (s.supported_types && Array.isArray(s.supported_types)) {
                    s.supported_types.forEach(t => types.add(t));
                }
            });
        }

        const sortedTypes = Array.from(types).sort();
        datalist.innerHTML = sortedTypes.map(t => `<option value="${t}">`).join('');
    },

    addManualIOC: () => {
        const idInput = document.getElementById('manual-id');
        const typeInput = document.getElementById('manual-type');
        
        const val = idInput.value.trim();
        const type = typeInput.value.trim();

        if (!val || !type) return showToast("Please enter both identifier and type.");

        const exists = state.manualIocs.some(i => i.value === val && i.type === type);
        if (exists) return showToast("IOC already staged.");

        state.manualIocs.push({ value: val, type: type });
        idInput.value = '';
        typeInput.value = '';
        idInput.focus();
        
        app.renderManualList();
    },

    removeManualIOC: (index) => {
        state.manualIocs.splice(index, 1);
        app.renderManualList();
    },

    renderManualList: () => {
        const container = document.getElementById('manual-ioc-list');
        const countBadge = document.getElementById('manual-count');
        const placeholder = document.getElementById('manual-placeholder');
        
        if (countBadge) countBadge.textContent = `${state.manualIocs.length} Staged`;
        if (!container) return;

        if (state.manualIocs.length === 0) {
            container.innerHTML = '';
            if(placeholder) placeholder.classList.remove('d-none');
            return;
        }

        if(placeholder) placeholder.classList.add('d-none');

        container.innerHTML = state.manualIocs.map((ioc, idx) => `
            <span class="badge rounded-pill bg-white text-dark border ps-3 pe-2 py-2 d-flex align-items-center gap-2 shadow-sm">
                <span class="font-monospace fw-bold text-primary">${ioc.value}</span>
                <span class="text-muted border-start ps-2 small text-uppercase" style="font-size: 0.7rem;">${ioc.type}</span>
                <i class="bi bi-x-circle-fill text-secondary opacity-50 hover-opacity-100" 
                   onclick="app.removeManualIOC(${idx})" 
                   style="cursor:pointer; font-size: 0.9rem;"></i>
            </span>
        `).join('');
    },

    filterServices: (term) => {
        const lowerTerm = term.toLowerCase().trim();
        const items = document.querySelectorAll('.service-item');
        
        const extractedIocs = app.extractIOCs(term);
        const detectedTypes = new Set(extractedIocs.map(i => i.type.toLowerCase()));

        items.forEach(item => {
            const label = item.getAttribute('data-label');
            const name = item.getAttribute('data-name');
            const typesStr = item.getAttribute('data-types');
            const supportedTypes = typesStr ? typesStr.split(',') : [];

            let matches = false;

            if (label.includes(lowerTerm) || name.includes(lowerTerm) || typesStr.includes(lowerTerm)) {
                matches = true;
            }

            if (!matches && detectedTypes.size > 0) {
                const hasSupportedType = supportedTypes.some(t => detectedTypes.has(t));
                if (hasSupportedType) {
                    matches = true;
                }
            }

            if (matches) {
                item.classList.remove('d-none');
                item.classList.add('d-flex');
            } else {
                item.classList.add('d-none');
                item.classList.remove('d-flex');
            }
        });
    },

    toggleService: (name) => {
        const checkbox = document.getElementById(`chk-${name}`);
        const row = document.getElementById(`row-${name}`);
        
        if (state.selectedServices.has(name)) {
            state.selectedServices.delete(name);
            checkbox.checked = false;
            row.classList.remove('selected');
        } else {
            state.selectedServices.add(name);
            checkbox.checked = true;
            row.classList.add('selected');
        }
    },

    selectAllServices: (select) => {
        const visibleItems = Array.from(document.querySelectorAll('.service-item:not(.d-none)'));
        visibleItems.forEach(item => {
            const checkbox = item.querySelector('input[type="checkbox"]');
            const name = checkbox.value;
            const isSelected = state.selectedServices.has(name);
            
            if (select && !isSelected) app.toggleService(name);
            if (!select && isSelected) app.toggleService(name);
        });
    },

    clearInput: () => {
        const inputEl = document.getElementById('input-text');
        const countEl = document.getElementById('ioc-count');
        if(inputEl) inputEl.value = '';
        if(countEl) countEl.innerHTML = '<i class="bi bi-crosshair me-1"></i>0 artifacts detected';
        
        state.manualIocs = [];
        app.renderManualList();
        
        const placeholder = document.getElementById('manual-placeholder');
        if(placeholder) placeholder.classList.remove('d-none');
    },

    startAnalysis: async () => {
        const text = document.getElementById('input-text').value;
        const textIocs = text ? app.extractIOCs(text) : [];
        
        const allIocs = [...textIocs];
        state.manualIocs.forEach(m => {
            if (!allIocs.some(e => e.value === m.value && e.type === m.type)) {
                allIocs.push(m);
            }
        });
        
        if (allIocs.length === 0) return showToast("No valid IOCs found (Regex or Manual).");
        if (allIocs.length > window.HuntsmanConfig.maxIocSubmissionLimit) {
            return showToast(`Submission limit exceeded. Please submit no more than ${window.HuntsmanConfig.maxIocSubmissionLimit} IOCs at a time.`, "danger");
        }
        if (state.selectedServices.size === 0) return showToast("Please select at least one enrichment module.");

        const tasksToSubmit = [];
        allIocs.forEach(ioc => {
            state.selectedServices.forEach(serviceName => {
                const serviceDef = state.services.find(s => s.name === serviceName);
                if (serviceDef && serviceDef.supported_types.includes(ioc.type)) {
                    tasksToSubmit.push({
                        service_name: serviceName,
                        identifier: ioc.value,
                        identifier_type: ioc.type
                    });
                }
            });
        });

        if (tasksToSubmit.length === 0) return alert("The selected modules do not support any of the provided indicator types.");

        try {
            const res = await fetch(window.HuntsmanConfig.urls.analyzeBulk, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCookie('csrftoken') },
                body: JSON.stringify({ tasks: tasksToSubmit })
            });
            const data = await res.json();
            
            state.activeTaskIds = data.task_ids;
            state.stixObjects.clear();
            state.correlationMatches = {};
            state.tasks = {};
            
            app.switchView('view-monitor');
            app.startPolling(state.activeTaskIds);
        } catch (err) {
            alert("Task submission failed.");
        }
    },

    startPolling: (taskIdsToPoll, isPivot = false) => {
        const progressBar = document.getElementById('progress-bar');
        const tbody = document.getElementById('tasks-table-body');
        
        const rowHtml = taskIdsToPoll.map(id => `
            <tr id="row-${id}">
                <td><span class="badge bg-secondary">PENDING</span></td>
                <td id="svc-${id}">Loading...</td>
                <td id="ident-${id}" class="font-monospace">...</td>
                <td id="type-${id}">...</td>
            </tr>
        `).join('');

        if (!isPivot) {
            tbody.innerHTML = rowHtml;
        } else {
            tbody.insertAdjacentHTML('afterbegin', rowHtml);
        }

        const intervalId = setInterval(async () => {
            try {
                const res = await fetch(window.HuntsmanConfig.urls.tasksBulk, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCookie('csrftoken') },
                    body: JSON.stringify({ task_ids: taskIdsToPoll })
                });
                const tasks = await res.json();
                let completedCount = 0;
                if (Array.isArray(tasks)) {
                    tasks.forEach(task => {
                        state.tasks[task.id] = task;
                        const row = document.getElementById(`row-${task.id}`);
                        if (row) {
                            let badgeClass = 'bg-warning text-dark';
                            if (task.status === 'SUCCESS') badgeClass = 'bg-success';
                            if (task.status === 'FAILURE') badgeClass = 'bg-danger';
                            row.cells[0].innerHTML = `<span class="badge ${badgeClass}">${task.status}</span>`;
                            document.getElementById(`svc-${task.id}`).textContent = task.service_name;
                            document.getElementById(`ident-${task.id}`).textContent = task.identifier;
                            document.getElementById(`type-${task.id}`).innerHTML = `<span class="badge bg-light text-dark border">${task.identifier_type}</span>`;
                        }
                        if (['SUCCESS', 'FAILURE'].includes(task.status)) completedCount++;
                    });
                } else {
                    console.error("Expected an array of tasks, but received:", tasks);
                }

                if (!isPivot) {
                    const percent = Math.round((completedCount / taskIdsToPoll.length) * 100);
                    if (progressBar) {
                        progressBar.style.width = `${percent}%`;
                        progressBar.textContent = `${percent}%`;
                    }
                }

                if (completedCount === taskIdsToPoll.length) {
                    clearInterval(intervalId);
                    if (!isPivot) {
                        const statusMsg = document.getElementById('status-message');
                        if (statusMsg) statusMsg.innerHTML = 'Analysis Complete. Rendering Intelligence Graph...';
                        await app.runPostProcessing(taskIdsToPoll);
                    } else {
                        showToast("Pivot analysis completed. Updating graph...");
                        await app.runPostProcessing(taskIdsToPoll, true);
                    }
                }
            } catch (err) {
                console.error(err);
            }
        }, 2000);
        
        if(!isPivot) state.pollingInterval = intervalId;
    },

    runPostProcessing: async (taskIds, isPivot = false) => {
        try {
            for (const taskId of taskIds) {
                const task = state.tasks[taskId];
                if (task.status === 'SUCCESS') {
                    const corrRes = await fetch(window.HuntsmanConfig.urls.correlate, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCookie('csrftoken') },
                        body: JSON.stringify({ task_id: taskId })
                    });
                    const corrData = await corrRes.json();
                    state.tasks[taskId].correlation = corrData;
                    if (corrData.matches_found > 0) {
                        state.correlationMatches[task.identifier] = corrData.results
                            .filter(r => r.matches > 0).map(r => r.rule_title);
                    }
                }
            }

            const reportsPayload = taskIds
                .filter(id => state.tasks[id].status === 'SUCCESS')
                .map(id => ({ task_id: id, report_name: `Report-${id}` }));

            if (reportsPayload.length > 0) {
                const stixRes = await fetch(window.HuntsmanConfig.urls.stixBulk, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCookie('csrftoken') },
                    body: JSON.stringify({ reports: reportsPayload })
                });
                const stixData = await stixRes.json();
                await app.pollStixTaskAndFetch(stixData.task_id);
            }

            if (!isPivot) {
                const statusMsg = document.getElementById('status-message');
                if (statusMsg) {
                    statusMsg.className = 'alert alert-success border-0 shadow-sm';
                    statusMsg.innerHTML = '<i class="bi bi-check-circle-fill me-2"></i>Investigation Complete';
                }
                app.renderResults();
                ExplorerManager.prepareExplorerData(); 
                app.switchView('view-results');
                app.toggleViewMode('graph');
                setTimeout(() => app.initGraph(), 500);
            } else {
                GraphManager.updateGraph();
                GraphManager.generateLegend();
                app.renderResults(); 
                ExplorerManager.prepareExplorerData();
            }
        } catch (err) {
            console.error(err);
        }
    },

    pollStixTaskAndFetch: async (stixTaskId) => {
        return new Promise((resolve) => {
            const interval = setInterval(async () => {
                const res = await fetch(window.HuntsmanConfig.urls.tasksBulk, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCookie('csrftoken') },
                    body: JSON.stringify({ task_ids: [stixTaskId] })
                });
                const data = await res.json();
                if (data[0].status === 'SUCCESS') {
                    clearInterval(interval);
                    await app.fetchStixBundle(stixTaskId);
                    resolve();
                } else if (data[0].status === 'FAILURE') {
                    clearInterval(interval);
                    resolve();
                }
            }, 2000);
        });
    },

    fetchStixBundle: async (stixTaskId) => {
        try {
            const query = `from 'stixdata' | task_id == '${stixTaskId}'`;
            const submitRes = await fetch(window.HuntsmanConfig.urls.query, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCookie('csrftoken') },
                body: JSON.stringify({ query: query })
            });
            const submitData = await submitRes.json();
            await new Promise(resolve => {
                const qInt = setInterval(async () => {
                    const poll = await fetch(window.HuntsmanConfig.urls.tasksBulk, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCookie('csrftoken') },
                        body: JSON.stringify({ task_ids: [submitData.task_id] })
                    });
                    const pData = await poll.json();
                    if (pData[0].status === 'SUCCESS') {
                        clearInterval(qInt);
                        const results = pData[0].full_result || [];
                        if (results.length > 0) {
                            const bundle = results[0];
                            (bundle.objects || []).forEach(obj => {
                                const graphId = GraphManager.getGraphId(obj);
                                if(graphId) state.stixObjects.set(graphId, obj);
                            });
                        }
                        resolve();
                    } else if (pData[0].status === 'FAILURE') {
                        clearInterval(qInt);
                        resolve();
                    }
                }, 1000);
            });
        } catch (e) { console.error(e); }
    },

    initGraph: () => {
        GraphManager.initGraph(app); 
    },

    preparePivot: (nodeId, autoRun) => {
        if (!state.services) {
            return showToast("Services not loaded yet. Please wait.");
        }

        const [type, ...valParts] = nodeId.split(':');
        const value = valParts.join(':');
        
        const applicableServices = state.services.filter(s => {
            const supported = (s.supported_types || []).map(t => t.toLowerCase());
            return supported.includes(type.toLowerCase());
        });
        
        if (applicableServices.length === 0) return showToast(`No modules available for type: ${type}`);

        state.pendingPivot = { value, type, services: applicableServices };

        if (autoRun) {
            app.executePivot(true);
        } else {
            const modalBody = document.querySelector('#pivotModal .modal-body');
            const label = document.getElementById('pivot-node-label');
            
            if (modalBody) {
                const list = document.getElementById('pivot-services-list');
                if (list) {
                     list.innerHTML = applicableServices.map(s => `
                        <label class="list-group-item">
                            <input class="form-check-input me-2" type="checkbox" value="${s.name}" checked>
                            <span class="small">${s.label}</span>
                        </label>
                    `).join('');
                }
            }

            if (label) label.textContent = value;
            if (state.pivotModal) state.pivotModal.show();
        }
    },

    togglePivotSelection: (select) => {
        const container = document.getElementById('pivot-services-list');
        if (!container) return;
        const checkboxes = container.querySelectorAll('input[type="checkbox"]');
        checkboxes.forEach(cb => cb.checked = select);
    },

    hidePivotModal: () => {
        if (state.pivotModal) state.pivotModal.hide();
    },


    openAddObjectModal: () => {
        const nameInput = document.getElementById('new-obj-name');
        const typeInput = document.getElementById('new-obj-type');
        const descInput = document.getElementById('new-obj-description');
        const labelsInput = document.getElementById('new-obj-labels');
        const hiddenId = document.getElementById('obj-hidden-id');
        
        if (nameInput) nameInput.value = '';
        if (typeInput) {
            typeInput.value = 'identity';
            typeInput.disabled = false; 
        }
        if (descInput) descInput.value = '';
        if (labelsInput) labelsInput.value = '';
        if (hiddenId) hiddenId.value = '';

        if (state.addObjectModal) state.addObjectModal.show();
    },

    editObject: (obj) => {
        const nameInput = document.getElementById('new-obj-name');
        const typeInput = document.getElementById('new-obj-type');
        const descInput = document.getElementById('new-obj-description');
        const labelsInput = document.getElementById('new-obj-labels');
        const hiddenId = document.getElementById('obj-hidden-id');
        
        if (hiddenId) hiddenId.value = GraphManager.getGraphId(obj);
        if (typeInput) {
            typeInput.value = obj.type;
            typeInput.disabled = true; 
        }
        if (nameInput) nameInput.value = obj.name || obj.value || "";
        if (descInput) descInput.value = obj.description || "";
        if (labelsInput) labelsInput.value = (obj.labels || []).join(', ');

        if (state.addObjectModal) state.addObjectModal.show();
    },

    saveStixObject: () => {
        const nameInput = document.getElementById('new-obj-name');
        const typeInput = document.getElementById('new-obj-type');
        const descInput = document.getElementById('new-obj-description');
        const labelsInput = document.getElementById('new-obj-labels');
        const hiddenId = document.getElementById('obj-hidden-id');
        
        const name = nameInput.value.trim();
        const type = typeInput.value;
        const desc = descInput.value.trim();
        const labelsStr = labelsInput.value.trim();
        const graphId = hiddenId.value;

        if (!name) return showToast("Please enter a name or value.");

        const labels = labelsStr ? labelsStr.split(',').map(s => s.trim()).filter(s => s) : [];
        const now = new Date().toISOString();

        let stixObj;

        if (graphId && state.stixObjects.has(graphId)) {
            stixObj = state.stixObjects.get(graphId);
            stixObj.modified = now;
            stixObj.name = name; 
            if (stixObj.value !== undefined) stixObj.value = name;
            
            if (desc) stixObj.description = desc;
            if (labels.length > 0) stixObj.labels = labels;
            
            showToast("Object updated.", "success");
        } else {
            const uuid = crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2, 15);
            const stixId = `${type}--${uuid}`;
            
            stixObj = {
                type: type,
                spec_version: "2.1",
                id: stixId,
                created: now,
                modified: now,
                name: name
            };
            if (desc) stixObj.description = desc;
            if (labels.length > 0) stixObj.labels = labels;

            showToast("Object created.", "success");
        }

        const newGraphId = GraphManager.getGraphId(stixObj);
        
        if (graphId && graphId !== newGraphId) {
            state.stixObjects.delete(graphId);
        }
        
        state.stixObjects.set(newGraphId, stixObj);
        
        GraphManager.updateGraph();
        GraphManager.generateLegend();

        if (state.addObjectModal) state.addObjectModal.hide();
    },

    startConnection: (sourceId) => {
        state.connectionSource = sourceId;
        showToast("Select a target node to connect.", "info");
    },

    openRelationshipModal: (source, target, rel = null) => {
        if (source === target) return showToast("Cannot connect a node to itself.");
    
        const sourceObj = state.stixObjects.get(source);
        const targetObj = state.stixObjects.get(target);
    
        if (!sourceObj || !targetObj) return;
    
        state.pendingRel = { source, target, id: rel ? rel.id : null };
    
        document.getElementById('rel-source-display').textContent = sourceObj.name || sourceObj.value;
        document.getElementById('rel-target-display').textContent = targetObj.name || targetObj.value;
        
        const typeSelect = document.getElementById('rel-type');
        typeSelect.value = rel ? rel.relationship_type : 'related-to';
    
        if (state.relationshipModal) state.relationshipModal.show();
    
        state.connectionSource = null;
    },

    editRelationship: (rel) => {
        const sourceObj = Array.from(state.stixObjects.values()).find(o => o.id === rel.source_ref);
        const targetObj = Array.from(state.stixObjects.values()).find(o => o.id === rel.target_ref);
        if (sourceObj && targetObj) {
            const sourceId = GraphManager.getGraphId(sourceObj);
            const targetId = GraphManager.getGraphId(targetObj);
            app.openRelationshipModal(sourceId, targetId, rel);
        }
    },

    createRelationship: () => {
        const { source, target, id } = state.pendingRel;
        const typeSelect = document.getElementById('rel-type');
        const relType = typeSelect.value;
        const now = new Date().toISOString();

        if (id) {
            const relObj = state.stixObjects.get(id);
            relObj.relationship_type = relType;
            relObj.modified = now;
            showToast("Relationship updated.", "success");
        } else {
            const sourceObj = state.stixObjects.get(source);
            const targetObj = state.stixObjects.get(target);
            const uuid = crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2, 15);
            
            const relObj = {
                type: "relationship",
                spec_version: "2.1",
                id: `relationship--${uuid}`,
                created: now,
                modified: now,
                relationship_type: relType,
                source_ref: sourceObj.id,
                target_ref: targetObj.id
            };
            state.stixObjects.set(relObj.id, relObj);
            showToast("Relationship created.", "success");
        }
        
        GraphManager.updateGraph();
        
        if (state.relationshipModal) state.relationshipModal.hide();
    },


    defang: (text) => {
        if (!text) return "";
        return text
            .replace(/\./g, "[.]")
            .replace(/http:/gi, "hxxp:")
            .replace(/https:/gi, "hxxps:");
    },

    copyToClipboard: async (text) => {
        try {
            await navigator.clipboard.writeText(text);
            showToast("Copied to clipboard!", "success");
        } catch (err) {
            console.error("Failed to copy:", err);
            showToast("Failed to copy to clipboard.", "danger");
        }
    },

    generateAnalystSummary: (identifier, tasks) => {
        const successfulTasks = tasks.filter(t => t.status !== 'FAILURE');
        if (successfulTasks.length === 0) return "";
        
        const defangedId = app.defang(identifier);
        const type = successfulTasks[0]?.identifier_type || "Unknown";

        const serviceLines = successfulTasks.map(t => {
            const matches = t.correlation?.matches_found || 0;
            let matchText = "No Indicators";
            if (matches > 0) matchText = `${matches} Matches`;
            return `- ${t.service_name}: ${matchText}`;
        });

        const detectionLines = [];
        successfulTasks.forEach(t => {
            if (t.correlation?.results) {
                const activeRules = t.correlation.results.filter(r => r.matches > 0);
                if (activeRules.length > 0) {
                    detectionLines.push(`[${t.service_name}]`);
                    activeRules.forEach(r => detectionLines.push(`  - ${r.rule_title}`));
                }
            }
        });

        return [
            `[Huntsman] Investigation Report`,
            `Target: ${defangedId} (${type})`,
            `\nModule Summary:`,
            ...serviceLines,
            detectionLines.length > 0 ? `\nDetections:` : `\nDetections: None`,
            ...detectionLines
        ].join('\n');
    },

    copyReport: (identifier) => {
        const tasks = Object.values(state.tasks).filter(t => 
            t.identifier === identifier && state.activeTaskIds.includes(t.id) && t.status !== 'FAILURE'
        );
        
        if (tasks.length > 0) {
            const summary = app.generateAnalystSummary(identifier, tasks);
            app.copyToClipboard(summary);
        } else {
            showToast("No successful data available for report.", "warning");
        }
    },

    copyAllReports: () => {
        const tasksById = {};
        state.activeTaskIds.forEach(id => {
            const task = state.tasks[id];
            if (!task || task.status === 'FAILURE') return;
            if (!tasksById[task.identifier]) tasksById[task.identifier] = [];
            tasksById[task.identifier].push(task);
        });

        if (Object.keys(tasksById).length === 0) return showToast("No data to copy.", "warning");

        const allReports = Object.entries(tasksById).map(([identifier, tasks]) => {
            return app.generateAnalystSummary(identifier, tasks);
        }).join('\n\n' + '-'.repeat(40) + '\n\n');

        app.copyToClipboard(allReports);
    },

    renderResults: () => {
        const container = document.getElementById('results-accordion');
        if(!container) return;
        
        const tasksById = {};
        state.activeTaskIds.forEach(id => {
            const task = state.tasks[id];
            if (!task || task.status === 'FAILURE') return;
            if (!tasksById[task.identifier]) tasksById[task.identifier] = [];
            tasksById[task.identifier].push(task);
        });

        if (Object.keys(tasksById).length === 0) {
            container.innerHTML = '';
            return;
        }
        
        const copyAllBtn = `
            <div class="d-flex justify-content-end mb-3">
                <button class="btn btn-sm btn-outline-primary" onclick="app.copyAllReports()">
                    <i class="bi bi-clipboard-data me-2"></i>Copy Results
                </button>
            </div>
        `;

        const itemsHtml = Object.entries(tasksById).map(([identifier, tasks], index) => {
            const defangedId = app.defang(identifier);
            const type = tasks[0].identifier_type;
            
            let totalMatches = 0;
            let successCount = 0;
            
            tasks.forEach(t => {
                if (t.status === 'SUCCESS') successCount++;
                if (t.correlation?.matches_found) totalMatches += t.correlation.matches_found;
            });

            let badgeClass = 'bg-secondary'; 
            let badgeText = 'No Match';

            if (totalMatches > 0) {
                badgeClass = 'bg-info';
                badgeText = 'Matched';
            }
            
            return `
                <div class="card mb-3 shadow-sm border-0">
                    <div class="card-header bg-white d-flex justify-content-between align-items-center py-3" id="heading${index}">
                        <div class="d-flex align-items-center flex-wrap gap-2">
                            <span class="fw-bold font-monospace fs-5 text-dark">${defangedId}</span>
                            <span class="badge bg-light text-dark border">${type}</span>
                            <span class="badge ${badgeClass}">${badgeText}</span>
                        </div>
                        <button class="btn btn-sm btn-outline-secondary" type="button" data-bs-toggle="collapse" data-bs-target="#collapse${index}">
                            <i class="bi bi-chevron-down"></i>
                        </button>
                    </div>
                    <div id="collapse${index}" class="collapse show" data-bs-parent="#results-accordion">
                        <div class="card-body bg-light border-top">
                            <div class="list-group shadow-sm">
                                ${tasks.map(task => app.renderServiceRow(task)).join('')}
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }).join('');

        container.innerHTML = copyAllBtn + itemsHtml;
        document.querySelectorAll('pre code').forEach((el) => hljs.highlightElement(el));
    },

    renderServiceRow: (task) => {
        const matches = task.correlation?.matches_found || 0;
        let badgeClass = 'bg-secondary';
        let badgeText = 'No Match(es)';

        if (matches > 0) {
            badgeClass = 'bg-danger';
            badgeText = `${matches} Match(es)`;
        }

        let detectionsHtml = '';
        if (matches > 0 && task.correlation?.results) {
             detectionsHtml = `<ul class="mb-0 mt-2 text-danger small fw-bold ps-3">
                ${task.correlation.results.filter(r => r.matches > 0).map(r => `<li>${r.rule_title}<br><small class="fw-normal text-muted">${r.description}</small></li>`).join('')}
             </ul>`;
        }

        return `
            <div class="list-group-item border-start-0 border-end-0">
                <div class="d-flex w-100 justify-content-between align-items-start">
                    <div class="me-3">
                        <div class="fw-bold text-dark text-capitalize">${task.service_name}</div>
                        ${detectionsHtml}
                    </div>
                    <div class="d-flex flex-column align-items-end gap-2">
                        <span class="badge ${badgeClass}">${badgeText}</span>
                    </div>
                </div>
            </div>
        `;
    },

    switchView: (viewId) => {
        ['view-input', 'view-monitor', 'view-results'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.classList.add('d-none');
        });
        const active = document.getElementById(viewId);
        if (active) active.classList.remove('d-none');
    },

    toggleViewMode: (mode) => {
        const graphDiv = document.getElementById('graph-container');
        const listDiv = document.getElementById('list-container');
        const explorerDiv = document.getElementById('explorer-container');
        
        graphDiv.classList.add('d-none');
        listDiv.classList.add('d-none');
        explorerDiv.classList.add('d-none');

        if (mode === 'graph') {
            graphDiv.classList.remove('d-none');
            if (state.cy) state.cy.resize();
        } else if (mode === 'list') {
            listDiv.classList.remove('d-none');
        } else if (mode === 'explorer') {
            explorerDiv.classList.remove('d-none');
            ExplorerManager.runExplorerQuery(); 
        }
    },

    runExplorerQuery: ExplorerManager.runExplorerQuery,

    resetView: () => {
        app.clearInput();
        
        state.activeTaskIds = [];
        state.tasks = {};
        state.stixObjects.clear();
        state.correlationMatches = {};
        state.hiddenTypes.clear();
        state.explorerData = null;

        if (state.pollingInterval) {
            clearInterval(state.pollingInterval);
            state.pollingInterval = null;
        }
        
        if (state.cy) {
            try {
                state.cy.destroy();
            } catch(e) {
                console.error(e);
            }
            state.cy = null;
        }
        
        const tbody = document.getElementById('tasks-table-body');
        if (tbody) tbody.innerHTML = '';

        const prog = document.getElementById('progress-bar');
        if (prog) {
            prog.style.width = '0%';
            prog.textContent = '0%';
        }

        const msg = document.getElementById('status-message');
        if (msg) {
            msg.className = 'd-flex align-items-center text-muted small mb-3';
            msg.innerHTML = '<div class="spinner-border spinner-border-sm me-2"></div><span>Initializing analysis tasks...</span>';
        }
        
        const resultsAccordion = document.getElementById('results-accordion');
        if (resultsAccordion) resultsAccordion.innerHTML = '';

        const explorerResults = document.getElementById('explorer-results');
        if (explorerResults) explorerResults.innerHTML = '';

        state.selectedServices.clear();
        document.querySelectorAll('.service-item input[type="checkbox"]').forEach(cb => {
            cb.checked = false;
        });
        document.querySelectorAll('.service-item').forEach(item => {
            item.classList.remove('selected');
            item.classList.remove('d-none');
            item.classList.add('d-flex');
        });

        const searchEl = document.getElementById('service-search');
        if (searchEl) searchEl.value = '';

        ExplorerManager.reset();

        app.switchView('view-input');
    },

    executePivot: async (all = false) => {
        const { value, type, services } = state.pendingPivot;
        let selectedNames = [];

        if (all) {
            selectedNames = services.map(s => s.name);
        } else {
            document.querySelectorAll('#pivot-services-list input:checked').forEach(cb => selectedNames.push(cb.value));
            if (state.pivotModal) state.pivotModal.hide();
        }

        if (selectedNames.length === 0) return;
        showToast(`Executing pivot on ${value}...`);

        const tasks = selectedNames.map(svc => ({
            service_name: svc,
            identifier: value,
            identifier_type: type
        }));

        try {
            const res = await fetch(window.HuntsmanConfig.urls.analyzeBulk, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCookie('csrftoken') },
                body: JSON.stringify({ tasks: tasks })
            });
            const data = await res.json();
            state.activeTaskIds.push(...data.task_ids);
            app.startPolling(data.task_ids, true); 
        } catch (e) {
            showToast("Pivot submission failed.");
            console.error(e);
        }
    },

    exportBundle: GraphManager.exportBundle,

    updateLayout: GraphManager.updateLayout,
    setZoom: GraphManager.setZoom,
    toggleFullScreen: GraphManager.toggleFullScreen,
    exportGraph: GraphManager.exportGraph,
    hideNodeDetails: GraphManager.hideNodeDetails
};

window.app = app; 
document.addEventListener('DOMContentLoaded', app.init);
