import { state } from './state.js';
import { SuperDB } from './superdb.js';
import { showToast, getCookie } from './utils.js';

export const ExplorerManager = {
    currentData: null,
    currentHeaders: null,
    viewMode: 'table',
    
    pagination: {
        page: 1,
        limit: 50
    },
    
    sortState: {
        column: null,
        asc: true
    },

    initSuperDB: async () => {
        const statusEl = document.getElementById('zq-status');
        try {
            if(statusEl) statusEl.textContent = "SuperDB Engine: Loading...";
            state.superdb = await SuperDB.instantiate(window.HuntsmanConfig.wasmPath);
            if(statusEl) statusEl.textContent = "SuperDB Engine: Ready";
            
            await ExplorerManager.initToolbarAndQueries();
        } catch(e) {
            console.error(e);
            if(statusEl) statusEl.textContent = "SuperDB Engine: Failed to Load";
        }
    },

    initToolbarAndQueries: async () => {
        const queriesBar = document.getElementById('predefined-queries-bar');
        if (!queriesBar) return;

        queriesBar.innerHTML = '';
        queriesBar.className = "mt-3 pt-2 border-top d-flex flex-wrap gap-2 align-items-center";

        const existingRunBtn = document.getElementById('btn-run-zq');
        const textarea = document.getElementById('zq-input');
        
        if (existingRunBtn && textarea) {
            textarea.classList.add('rounded-end');
            existingRunBtn.className = "btn btn-primary btn-sm";
            existingRunBtn.innerHTML = ''; 
            const icon = document.createElement('i');
            icon.className = 'bi bi-play-fill me-1';
            existingRunBtn.appendChild(icon);
            existingRunBtn.appendChild(document.createTextNode('Run Query'));
            queriesBar.appendChild(existingRunBtn);
        }

        const viewGroup = document.createElement('div');
        viewGroup.className = "btn-group btn-group-sm";
        viewGroup.role = "group";
        
        const btnTable = document.createElement('button');
        btnTable.className = `btn ${ExplorerManager.viewMode === 'table' ? 'btn-secondary' : 'btn-outline-secondary'}`;
        const iconTable = document.createElement('i');
        iconTable.className = 'bi bi-table me-1';
        btnTable.appendChild(iconTable);
        btnTable.appendChild(document.createTextNode('Table'));
        btnTable.onclick = () => ExplorerManager.switchView('table');
        
        const btnRaw = document.createElement('button');
        btnRaw.className = `btn ${ExplorerManager.viewMode === 'raw' ? 'btn-secondary' : 'btn-outline-secondary'}`;
        const iconRaw = document.createElement('i');
        iconRaw.className = 'bi bi-code-slash me-1';
        btnRaw.appendChild(iconRaw);
        btnRaw.appendChild(document.createTextNode('Raw'));
        btnRaw.onclick = () => ExplorerManager.switchView('raw');

        viewGroup.appendChild(btnTable);
        viewGroup.appendChild(btnRaw);
        queriesBar.appendChild(viewGroup);

        const libraryGroup = document.createElement('div');
        libraryGroup.className = "dropdown";
        libraryGroup.innerHTML = `
            <button class="btn btn-outline-secondary btn-sm dropdown-toggle" type="button" data-bs-toggle="dropdown" aria-expanded="false">
                <i class="bi bi-journal-code me-1"></i>Query Library
            </button>
            <div class="dropdown-menu shadow p-0" style="min-width: 350px; max-width: 500px; z-index: 2000;">
                <div class="p-2 border-bottom sticky-top bg-white rounded-top">
                    <input type="text" class="form-control form-control-sm font-monospace" id="query-search-input" placeholder="Search predefined queries..." onclick="event.stopPropagation()">
                </div>
                <div id="query-dropdown-list" class="list-group list-group-flush" style="max-height: 300px; overflow-y: auto;">
                    <div class="p-3 text-center text-muted small">Loading...</div>
                </div>
            </div>
        `;
        queriesBar.appendChild(libraryGroup);

        const sep = document.createElement('div');
        sep.className = "border-start mx-2";
        sep.style.height = "20px";
        queriesBar.appendChild(sep);

        const createBtn = (id, text, iconClass, colorClass = "btn-outline-secondary") => {
            const btn = document.createElement('button');
            btn.id = id;
            btn.className = `btn btn-sm ${colorClass}`;
            btn.disabled = true;
            const icon = document.createElement('i');
            icon.className = `bi ${iconClass} me-1`;
            btn.appendChild(icon);
            btn.appendChild(document.createTextNode(text));
            return btn;
        };

        const btnExport = createBtn('btn-toolbar-export', 'Export CSV', 'bi-file-earmark-spreadsheet', 'btn-outline-success');
        const btnCopy = createBtn('btn-toolbar-copy', 'Copy', 'bi-clipboard', 'btn-outline-primary');
        const btnAi = createBtn('btn-toolbar-ai', 'AI Analyze', 'bi-robot', 'btn-primary');

        btnExport.onclick = () => ExplorerManager.exportToCSV(ExplorerManager.currentData, ExplorerManager.currentHeaders);
        
        btnCopy.onclick = () => {
            if (!ExplorerManager.currentData) return;
            let textToCopy;
            if (ExplorerManager.viewMode === 'raw') {
                textToCopy = JSON.stringify(ExplorerManager.currentData, null, 2);
            } else {
                const headers = ExplorerManager.currentHeaders || [];
                textToCopy = ExplorerManager.currentData.map(row => {
                    const rowObj = (typeof row !== 'object' || row === null) ? { 'value': row } : row;
                    const keys = headers.length > 0 ? headers : Object.keys(rowObj);
                    return keys.map(key => {
                        let val = rowObj[key];
                        if (typeof val === 'object' && val !== null) {
                            val = JSON.stringify(val);
                        }
                        return `${key}: ${val}`;
                    }).join('\n');
                }).join('\n\n');
            }
            navigator.clipboard.writeText(textToCopy).then(() => showToast("Copied to clipboard!", "success"));
        };

        btnAi.onclick = () => ExplorerManager.runAIAnalysis(ExplorerManager.currentData, btnAi);

        queriesBar.appendChild(btnExport);
        queriesBar.appendChild(btnCopy);
        queriesBar.appendChild(btnAi);

        await ExplorerManager.loadQueriesContent();
    },

    switchView: (mode) => {
        ExplorerManager.viewMode = mode;
        const queriesBar = document.getElementById('predefined-queries-bar');
        if(queriesBar) {
            const btns = queriesBar.querySelectorAll('.btn-group button');
            if(btns.length >= 2) {
                btns[0].className = `btn ${mode === 'table' ? 'btn-secondary' : 'btn-outline-secondary'}`;
                btns[1].className = `btn ${mode === 'raw' ? 'btn-secondary' : 'btn-outline-secondary'}`;
            }
        }
        const container = document.getElementById('explorer-results');
        if(ExplorerManager.currentData && container) {
            container.innerHTML = '';
            if(mode === 'raw') {
                ExplorerManager.renderRawJson(ExplorerManager.currentData, container);
            } else {
                try {
                    ExplorerManager.renderExplorerTable(ExplorerManager.currentData, container);
                } catch (e) {
                    console.warn("Table render error, switching to raw", e);
                    ExplorerManager.switchView('raw');
                }
            }
        }
    },

    loadQueriesContent: async () => {
        const listContainer = document.getElementById('query-dropdown-list');
        const searchInput = document.getElementById('query-search-input');
        if (!listContainer) return;

        try {
            const res = await fetch('/api/queries/predefined/');
            if (!res.ok) throw new Error("Failed to fetch queries");
            
            const queries = await res.json();
            listContainer.innerHTML = '';

            const renderItem = (q) => {
                const title = q.title || q.name || "Untitled";
                const queryVal = q.query_string || q.query || "";
                const desc = q.description || "";

                const item = document.createElement('a');
                item.href = "#";
                item.className = "list-group-item list-group-item-action py-2";
                
                const headerDiv = document.createElement('div');
                headerDiv.className = "d-flex w-100 justify-content-between";
                const h6 = document.createElement('h6');
                h6.className = "mb-1 fw-bold small";
                h6.textContent = title;
                headerDiv.appendChild(h6);
                
                const small = document.createElement('small');
                small.className = "text-muted d-block text-truncate font-monospace";
                small.style.fontSize = "0.7rem";
                small.textContent = queryVal;

                item.appendChild(headerDiv);
                item.appendChild(small);
                
                item.onclick = (e) => {
                    e.preventDefault();
                    const input = document.getElementById('zq-input');
                    if (input) {
                        input.value = queryVal;
                        ExplorerManager.runExplorerQuery();
                    }
                };
                
                item.dataset.searchText = (title + " " + queryVal + " " + desc).toLowerCase();
                listContainer.appendChild(item);
            };

            if (Array.isArray(queries)) {
                queries.forEach(q => renderItem(q));
            } else {
                Object.values(queries).forEach(list => {
                    if(Array.isArray(list)) list.forEach(q => renderItem(q));
                });
            }

            if (listContainer.children.length === 0) {
                const noQueries = document.createElement('div');
                noQueries.className = "p-3 text-center text-muted small";
                noQueries.textContent = "No queries found.";
                listContainer.appendChild(noQueries);
            }

            if (searchInput) {
                searchInput.addEventListener('input', (e) => {
                    const term = e.target.value.toLowerCase();
                    const items = listContainer.querySelectorAll('a');
                    items.forEach(item => {
                        if (item.dataset.searchText.includes(term)) {
                            item.classList.remove('d-none');
                        } else {
                            item.classList.add('d-none');
                        }
                    });
                });
            }

        } catch (e) {
            console.warn("Huntsman: Error loading queries", e);
            listContainer.innerHTML = '';
            const errDiv = document.createElement('div');
            errDiv.className = "p-2 text-danger small text-center";
            errDiv.textContent = "Error loading queries";
            listContainer.appendChild(errDiv);
        }
    },

    prepareExplorerData: () => {
        const flatData = [];
        Object.values(state.tasks).forEach(task => {
            if (task.status === 'SUCCESS' && task.full_result) {
                 const base = {
                     _service: task.service_name,
                     _id: task.identifier,
                     _type: task.identifier_type,
                     _ts: task.completed_at
                 };
                 
                 let results = [];
                 if (task.full_result.data && Array.isArray(task.full_result.data)) {
                      results = task.full_result.data;
                 } else if (Array.isArray(task.full_result)) {
                      results = task.full_result;
                 } else {
                      results = [task.full_result];
                 }
                 
                 results.forEach(r => {
                     flatData.push({ ...base, ...r });
                 });
            }
        });
        state.explorerData = flatData.map(JSON.stringify).join('\n');
    },

    runExplorerQuery: async () => {
        if (!state.superdb) return showToast("SuperDB engine not ready.");
        if (!state.explorerData) return showToast("No analysis data to explore.");

        let query = document.getElementById('zq-input').value || '*';
        const lower = query.trim().toLowerCase();
        if (lower === '*' || lower === '') {
            query = 'yield this';
        } else if (lower.startsWith('from ')) {
             query = query.replace(/^\s*from\s+[\w*]+\s*(\|)?\s*/i, '');
             if (query === '') query = 'yield this';
        }

        const statusEl = document.getElementById('zq-status');
        const container = document.getElementById('explorer-results');
        
        if(statusEl) statusEl.textContent = "Executing...";
        container.style.opacity = "0.5";

        ['btn-toolbar-export', 'btn-toolbar-copy', 'btn-toolbar-ai'].forEach(id => {
            const btn = document.getElementById(id);
            if(btn) btn.disabled = true;
        });

        try {
            const res = await state.superdb.run({
                query: query,
                input: state.explorerData,
                inputFormat: "json", 
                outputFormat: "json"
            });

            container.innerHTML = "";
            
            if (res.error) {
                 const errorDiv = document.createElement('div');
                 errorDiv.className = "alert alert-danger font-monospace";
                 errorDiv.textContent = res.error;
                 container.appendChild(errorDiv);
                 if(statusEl) statusEl.textContent = "Query Failed";
            } else {
                 const resultData = res.data || res.output || res.result || (typeof res === 'string' ? res : '');
                 const lines = resultData.trim().split('\n').filter(l => l);
                 
                 if (lines.length === 0) {
                     const noResults = document.createElement('div');
                     noResults.className = "text-muted text-center mt-4";
                     noResults.textContent = "No results found.";
                     container.appendChild(noResults);
                 } else {
                     const objects = lines.map(l => JSON.parse(l));
                     ExplorerManager.currentData = objects;
                     ExplorerManager.pagination.page = 1;
                     ExplorerManager.sortState = { column: null, asc: true };
                     
                     if (ExplorerManager.viewMode === 'raw') {
                         ExplorerManager.renderRawJson(objects, container);
                     } else {
                         try {
                            ExplorerManager.renderExplorerTable(objects, container);
                         } catch (renderErr) {
                             console.warn("Table render failed, switching to raw", renderErr);
                             ExplorerManager.switchView('raw');
                         }
                     }
                 }
                 if(statusEl) statusEl.textContent = `Query returned ${lines.length} records`;
            }
        } catch (e) {
            console.error(e);
            container.innerHTML = '';
            const errDiv = document.createElement('div');
            errDiv.className = "alert alert-danger";
            errDiv.textContent = `Engine Error: ${e.message}`;
            container.appendChild(errDiv);
            if(statusEl) statusEl.textContent = "Engine Error";
        } finally {
            container.style.opacity = "1";
        }
    },

    renderRawJson: (data, container) => {
        ['btn-toolbar-export', 'btn-toolbar-copy', 'btn-toolbar-ai'].forEach(id => {
            const btn = document.getElementById(id);
            if(btn) btn.disabled = false;
        });

        container.innerHTML = '';
        
        const maxItems = 1000;
        let displayData = data;
        let warningMsg = null;

        if (data.length > maxItems) {
            displayData = data.slice(0, maxItems);
            warningMsg = document.createElement('div');
            warningMsg.className = "alert alert-warning py-2 mb-2 small";
            warningMsg.innerHTML = `<i class="bi bi-exclamation-triangle me-2"></i>Showing first ${maxItems} of ${data.length} records to prevent browser crash. Use <strong>Export CSV</strong> for full results.`;
        }

        if (warningMsg) container.appendChild(warningMsg);

        const pre = document.createElement('pre');
        pre.className = "bg-light p-3 border rounded font-monospace small";
        pre.style.maxHeight = "600px";
        pre.style.overflow = "auto";
        pre.textContent = JSON.stringify(displayData, null, 2);
        container.appendChild(pre);
    },

    renderExplorerTable: (data, container) => {
         if(!data || data.length === 0) return;
         
         container.innerHTML = '';
         
         const allKeys = new Set();
         data.forEach(row => {
             if (typeof row === 'object' && row !== null) {
                Object.keys(row).forEach(k => allKeys.add(k));
             } else {
                allKeys.add('value');
             }
         });
         
         const headers = Array.from(allKeys).sort((a, b) => {
             if (a.startsWith('_') && !b.startsWith('_')) return -1;
             if (!a.startsWith('_') && b.startsWith('_')) return 1;
             return a.localeCompare(b);
         });
         ExplorerManager.currentHeaders = headers;

         const totalPages = Math.ceil(data.length / ExplorerManager.pagination.limit);
         if (ExplorerManager.pagination.page > totalPages) ExplorerManager.pagination.page = 1;
         
         const startIdx = (ExplorerManager.pagination.page - 1) * ExplorerManager.pagination.limit;
         const endIdx = startIdx + ExplorerManager.pagination.limit;
         const pageData = data.slice(startIdx, endIdx);

         ['btn-toolbar-export', 'btn-toolbar-copy', 'btn-toolbar-ai'].forEach(id => {
            const btn = document.getElementById(id);
            if(btn) btn.disabled = false;
         });

         const tableWrapper = document.createElement('div');
         tableWrapper.className = "table-responsive border rounded";
         tableWrapper.style.maxHeight = "600px";
         tableWrapper.style.overflowX = "auto";
         tableWrapper.style.scrollBehavior = "smooth";

         const table = document.createElement('table');
         table.className = "table table-sm table-hover table-striped font-monospace small mb-0";
         table.id = "explorer-data-table";
         
         const thead = document.createElement('thead');
         thead.className = "sticky-top bg-white shadow-sm";
         const headerRow = document.createElement('tr');
         headerRow.className = "table-light";
         
         headers.forEach(h => {
             const th = document.createElement('th');
             th.style.cursor = "pointer";
             th.className = "text-nowrap";
             
             const textNode = document.createTextNode(h + ' ');
             th.appendChild(textNode);
             
             const icon = document.createElement('i');
             icon.className = "bi ms-1 text-muted";
             
             if (ExplorerManager.sortState.column === h) {
                 icon.className = `bi ms-1 ${ExplorerManager.sortState.asc ? 'bi-sort-alpha-down' : 'bi-sort-alpha-down-alt'} text-primary`;
             } else {
                 icon.className = "bi bi-arrow-down-up ms-1 text-muted opacity-25";
             }
             icon.style.fontSize = "0.7rem";
             th.appendChild(icon);
             
             th.onclick = () => ExplorerManager.sortTable(h, container);
             headerRow.appendChild(th);
         });
         thead.appendChild(headerRow);
         table.appendChild(thead);

         const tbody = document.createElement('tbody');
         pageData.forEach(row => {
             const tr = document.createElement('tr');
             
             const isPrimitive = typeof row !== 'object' || row === null;
             const rowObj = isPrimitive ? { 'value': row } : row;

             headers.forEach(h => {
                 const td = document.createElement('td');
                 td.className = "text-truncate";
                 td.style.maxWidth = "300px";
                 const val = rowObj[h];
                 
                 td.appendChild(ExplorerManager.renderCell(val));
                 td.title = typeof val === 'object' ? JSON.stringify(val, null, 2) : String(val);
                 tr.appendChild(td);
             });
             tbody.appendChild(tr);
         });
         table.appendChild(tbody);
         
         tableWrapper.appendChild(table);
         container.appendChild(tableWrapper);

         if (totalPages > 1) {
             ExplorerManager.renderPaginationControls(container, totalPages, data.length);
         }
    },

    renderPaginationControls: (container, totalPages, totalItems) => {
        const nav = document.createElement('nav');
        nav.className = "d-flex justify-content-between align-items-center mt-2 p-2 border rounded bg-light";
        
        const info = document.createElement('span');
        info.className = "text-muted small";
        const start = (ExplorerManager.pagination.page - 1) * ExplorerManager.pagination.limit + 1;
        const end = Math.min(start + ExplorerManager.pagination.limit - 1, totalItems);
        info.textContent = `Showing ${start}-${end} of ${totalItems}`;

        const ul = document.createElement('ul');
        ul.className = "pagination pagination-sm mb-0";

        const createPageItem = (text, pageNum, isActive = false, isDisabled = false) => {
            const li = document.createElement('li');
            li.className = `page-item ${isActive ? 'active' : ''} ${isDisabled ? 'disabled' : ''}`;
            
            const a = document.createElement('button');
            a.className = "page-link";
            a.textContent = text;
            a.onclick = () => {
                if (!isDisabled && !isActive) {
                    ExplorerManager.pagination.page = pageNum;
                    ExplorerManager.renderExplorerTable(ExplorerManager.currentData, container);
                }
            };
            li.appendChild(a);
            return li;
        };

        ul.appendChild(createPageItem('Prev', ExplorerManager.pagination.page - 1, false, ExplorerManager.pagination.page === 1));

        let pagesToShow = [];
        if (totalPages <= 7) {
            pagesToShow = Array.from({length: totalPages}, (_, i) => i + 1);
        } else {
            if (ExplorerManager.pagination.page <= 4) {
                pagesToShow = [1, 2, 3, 4, 5, '...', totalPages];
            } else if (ExplorerManager.pagination.page >= totalPages - 3) {
                pagesToShow = [1, '...', totalPages - 4, totalPages - 3, totalPages - 2, totalPages - 1, totalPages];
            } else {
                pagesToShow = [1, '...', ExplorerManager.pagination.page - 1, ExplorerManager.pagination.page, ExplorerManager.pagination.page + 1, '...', totalPages];
            }
        }

        pagesToShow.forEach(p => {
            if (p === '...') {
                const li = document.createElement('li');
                li.className = "page-item disabled";
                li.innerHTML = '<span class="page-link">...</span>';
                ul.appendChild(li);
            } else {
                ul.appendChild(createPageItem(p, p, p === ExplorerManager.pagination.page));
            }
        });

        ul.appendChild(createPageItem('Next', ExplorerManager.pagination.page + 1, false, ExplorerManager.pagination.page === totalPages));

        nav.appendChild(info);
        nav.appendChild(ul);
        container.appendChild(nav);
    },

    renderCell: (value) => {
        if (value === undefined || value === null) {
            const span = document.createElement('span');
            span.className = "text-muted";
            span.textContent = "-";
            return span;
        }
        
        if (typeof value === 'string') {
            if (value.match(/^https?:\/\//)) {
                const a = document.createElement('a');
                a.href = value;
                a.target = "_blank";
                a.className = "text-decoration-none text-truncate d-inline-block";
                a.style.maxWidth = "100%";
                a.textContent = value;
                return a;
            }
            return document.createTextNode(value);
        }
        
        if (Array.isArray(value)) {
            if (value.length === 0) {
                const span = document.createElement('span');
                span.className = "text-muted";
                span.textContent = "[]";
                return span;
            }
            const preview = value.length > 3 ? value.slice(0, 3).map(String).join(', ') + '...' : value.map(String).join(', ');
            
            const badge = document.createElement('span');
            badge.className = "badge bg-secondary bg-opacity-10 text-dark border me-1";
            badge.title = JSON.stringify(value);
            badge.textContent = '[List] ' + preview;
            return badge;
        }
        
        if (typeof value === 'object') {
            const jsonString = JSON.stringify(value);
            const truncatedString = jsonString.length > 50 ? jsonString.substring(0, 50) + '...' : jsonString;

            const badge = document.createElement('span');
            badge.className = "badge bg-info bg-opacity-10 text-dark border";
            badge.title = JSON.stringify(value, null, 2);
            badge.textContent = truncatedString;
            return badge;
        }
        
        return document.createTextNode(String(value));
    },

    sortTable: (column, container) => {
        if (!ExplorerManager.currentData) return;

        const isSameCol = ExplorerManager.sortState.column === column;
        const newAsc = isSameCol ? !ExplorerManager.sortState.asc : true;
        
        ExplorerManager.sortState = { column: column, asc: newAsc };

        ExplorerManager.currentData.sort((a, b) => {
            let valA = (typeof a === 'object' && a !== null) ? a[column] : a;
            let valB = (typeof b === 'object' && b !== null) ? b[column] : b;

            if (valA === undefined || valA === null) valA = '';
            if (valB === undefined || valB === null) valB = '';
            
            valA = String(valA).toLowerCase();
            valB = String(valB).toLowerCase();

            if (valA < valB) return newAsc ? -1 : 1;
            if (valA > valB) return newAsc ? 1 : -1;
            return 0;
        });

        ExplorerManager.renderExplorerTable(ExplorerManager.currentData, container);
    },

    exportToCSV: (data, headers) => {
        if (!data || !data.length) return;
        
        const safeHeaders = headers || Object.keys(data[0] || {});

        const csvRows = [];
        csvRows.push(safeHeaders.join(','));

        for (const row of data) {
            const rowObj = (typeof row !== 'object' || row === null) ? { 'value': row } : row;
            
            const values = safeHeaders.map(header => {
                let val = rowObj[header];
                if (val === undefined || val === null) val = "";
                else if (typeof val === 'object') val = JSON.stringify(val);
                
                const escaped = ('' + val).replace(/"/g, '""');
                return `"${escaped}"`;
            });
            csvRows.push(values.join(','));
        }

        const blob = new Blob([csvRows.join('\n')], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.setAttribute('hidden', '');
        a.setAttribute('href', url);
        a.setAttribute('download', `huntsman_export_${new Date().getTime()}.csv`);
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
    },

    runAIAnalysis: async (data, btnElement) => {
        const limit = 50;
        const truncatedData = data.slice(0, limit);
        
        btnElement.disabled = true;
        btnElement.innerHTML = '';
        const spinner = document.createElement('div');
        spinner.className = "spinner-border spinner-border-sm me-1";
        btnElement.appendChild(spinner);
        btnElement.appendChild(document.createTextNode('Queued'));

        const insightSection = document.getElementById('ai-insight-section');
        if (!insightSection) return;

        insightSection.classList.remove('d-none');
        insightSection.innerHTML = `
            <div class="p-4 text-center">
                <div class="spinner-grow text-primary mb-3" role="status" style="width: 3rem; height: 3rem;"></div>
                <h5 class="text-primary fw-bold">Submitting for Analysis...</h5>
                <p class="text-muted small mb-0">Processing ${truncatedData.length} records.</p>
            </div>
        `;

        try {
            const url = window.HuntsmanConfig.urls.aiAnalyze || '/api/ai/analyze/';
            
            const res = await fetch(url, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCookie('csrftoken')
                },
                body: JSON.stringify({
                    data: truncatedData,
                    prompt: "Analyze these results and identify key threats, anomalies, or summary findings. Provide a concise report."
                })
            });
            
            const submitResult = await res.json();
            if(!res.ok) throw new Error(submitResult.error || `Submission failed: ${res.status}`);
            
            const taskId = submitResult.task_id;
            if(!taskId) throw new Error("No task ID returned from server.");

            insightSection.innerHTML = `
                <div class="p-4 text-center">
                    <div class="spinner-border text-primary mb-3" role="status"></div>
                    <h5 class="text-primary fw-bold">Analyzing Data...</h5>
                    <p class="text-muted small mb-0">AI Model is generating insights.</p>
                    <p class="text-muted small">This may take 20-30 seconds.</p>
                </div>
            `;

            let attempts = 0;
            const maxAttempts = 60; 
            
            const poll = async () => {
                if (attempts >= maxAttempts) {
                    throw new Error("Analysis timed out. Please try again.");
                }
                
                const taskRes = await fetch(`/api/tasks/${taskId}/`);
                if(!taskRes.ok) throw new Error("Failed to check task status");
                
                const taskData = await taskRes.json();
                
                if (taskData.status === 'SUCCESS') {
                    return taskData.full_result;
                } else if (taskData.status === 'FAILURE') {
                    throw new Error(taskData.full_result?.error || "Task execution failed.");
                } else {
                    attempts++;
                    await new Promise(resolve => setTimeout(resolve, 1000));
                    return poll();
                }
            };

            const finalResult = await poll();
            
            const analysisText = finalResult.result || JSON.stringify(finalResult);
            
            const renderedHtml = typeof marked !== 'undefined' 
                ? marked.parse(analysisText) 
                : `<pre style="white-space: pre-wrap;">${analysisText}</pre>`;

            insightSection.innerHTML = '';
            
            const containerDiv = document.createElement('div');
            containerDiv.className = "p-3";
            
            const headerDiv = document.createElement('div');
            headerDiv.className = "d-flex justify-content-between align-items-start mb-3";
            
            const h5 = document.createElement('h5');
            h5.className = "text-success fw-bold mb-0";
            h5.innerHTML = '<i class="bi bi-stars me-2"></i>AI Insights';
            
            const closeBtn = document.createElement('button');
            closeBtn.className = "btn-close";
            closeBtn.onclick = () => {
                insightSection.classList.add('d-none');
                insightSection.innerHTML = '';
            };
            
            headerDiv.appendChild(h5);
            headerDiv.appendChild(closeBtn);
            
            const contentDiv = document.createElement('div');
            contentDiv.className = "bg-white p-3 rounded border";
            contentDiv.style.fontFamily = "inherit";
            contentDiv.style.lineHeight = "1.6";
            contentDiv.contentEditable = "true";
            
            contentDiv.innerHTML = renderedHtml;
            
            const footerDiv = document.createElement('div');
            footerDiv.className = "mt-2 text-muted small text-end";
            footerDiv.textContent = `Generated by AI based on top ${truncatedData.length} records`;
            
            containerDiv.appendChild(headerDiv);
            containerDiv.appendChild(contentDiv);
            containerDiv.appendChild(footerDiv);
            insightSection.appendChild(containerDiv);

        } catch(e) {
            console.error("AI Analysis Error:", e);
            insightSection.innerHTML = '';
            
            const alertDiv = document.createElement('div');
            alertDiv.className = "alert alert-danger m-3 d-flex justify-content-between align-items-center";
            
            const msgDiv = document.createElement('div');
            msgDiv.innerHTML = `<i class="bi bi-exclamation-triangle-fill me-2"></i><strong>Analysis Failed:</strong> ${e.message}`;
            
            const closeBtn = document.createElement('button');
            closeBtn.className = "btn-close";
            closeBtn.onclick = () => insightSection.classList.add('d-none');
            
            alertDiv.appendChild(msgDiv);
            alertDiv.appendChild(closeBtn);
            insightSection.appendChild(alertDiv);
        } finally {
            btnElement.disabled = false;
            btnElement.innerHTML = '';
            const icon = document.createElement('i');
            icon.className = "bi bi-robot me-1";
            btnElement.appendChild(icon);
            btnElement.appendChild(document.createTextNode('AI Analyze'));
        }
    },

    reset: () => {
        ExplorerManager.currentData = null;
        ExplorerManager.currentHeaders = null;
        ExplorerManager.viewMode = 'table';
        ExplorerManager.pagination = { page: 1, limit: 50 };
        ExplorerManager.sortState = { column: null, asc: true };

        const input = document.getElementById('zq-input');
        if (input) input.value = '';

        const container = document.getElementById('explorer-results');
        if (container) container.innerHTML = '';

        const statusEl = document.getElementById('zq-status');
        if (statusEl) statusEl.textContent = 'SuperDB Engine: Ready';

        ExplorerManager.switchView('table');
    }
};
