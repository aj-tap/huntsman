import { state } from './state.js';
import { TYPE_COLORS } from './utils.js';

const ICON_BASE_PATH = '/static/api/icons/';

const ICON_MAP = {
    // SDOs (Domain Objects)
    'attack-pattern': 'stix2-ttp-icons-png/attack-pattern-round-flat-300-dpi.png',
    'campaign': 'stix2-adversary-icons-png/campaign-round-flat-300-dpi.png',
    'course-of-action': 'stix2-ir-icons-png/coa-round-flat-300-dpi.png',
    'grouping': 'stix2-meta-icons-png/grouping-round-flat-300-dpi.png',
    'identity': 'stix2-meta-icons-png/identity-round-flat-300-dpi.png',
    'incident': 'stix2-ir-icons-png/incident-round-flat-300-dpi.png',
    'indicator': 'stix2-ir-icons-png/indicator-round-flat-300-dpi.png',
    'infrastructure': 'stix2-ttp-icons-png/infrastructure-round-flat-300-dpi.png',
    'intrusion-set': 'stix2-adversary-icons-png/intrusion-set-round-flat-300-dpi.png',
    'location': 'stix2-meta-icons-png/location-round-flat-300-dpi.png',
    'malware': 'stix2-ttp-icons-png/malware-round-flat-300-dpi.png',
    'malware-analysis': 'stix2-ttp-icons-png/malware-analysis-round-flat-300-dpi.png',
    'note': 'stix2-meta-icons-png/note-round-flat-300-dpi.png',
    'observed-data': 'stix2-ir-icons-png/observed-data-round-flat-300-dpi.png',
    'opinion': 'stix2-meta-icons-png/opinion-round-flat-300-dpi.png',
    'report': 'stix2-meta-icons-png/report-round-flat-300-dpi.png',
    'threat-actor': 'stix2-adversary-icons-png/threat-actor-round-flat-300-dpi.png',
    'tool': 'stix2-ttp-icons-png/tool-round-flat-300-dpi.png',
    'vulnerability': 'stix2-targeting-icons-png/vulnerability-round-flat-300-dpi.png',

    // SCOs (Observables)
    'artifact': 'stix2-sco2-icons/Artifact-Round.png',
    'autonomous-system': 'stix2-sco-network-traffic-icons-png/autonomous-system-round-flat-300-dpi.png',
    'directory': 'stix2-sco2-icons/Directory-Round.png',
    'domain-name': 'stix2-sco-network-address-icons-png/domain-name-round-flat-300-dpi.png',
    'email-addr': 'stix2-sco1-icons-png/email-addr-round-flat-300-dpi.png',
    'email-message': 'stix2-sco1-icons-png/email-msg-round-flat-300-dpi.png',
    'file': 'stix2-sco2-icons/File-Round.png',
    'ipv4-addr': 'stix2-sco-network-address-icons-png/ipv4-addr-round-flat-300-dpi.png',
    'ipv6-addr': 'stix2-sco-network-address-icons-png/ipv6-addr-round-flat-300-dpi.png',
    'mac-addr': 'stix2-sco-network-address-icons-png/mac-addr-round-flat-300-dpi.png',
    'mutex': 'stix2-sco2-icons/Mutex-Round.png',
    'network-traffic': 'stix2-sco-network-traffic-icons-png/network-traffic-round-flat-300-dpi.png',
    'process': 'stix2-sco2-icons/Process-Round.png',
    'software': 'stix2-sco2-icons/Software-Round.png',
    'url': 'stix2-sco2-icons/URL-Round.png',
    'user-account': 'stix2-sco1-icons-png/user-account-round-flat-300-dpi.png',
    'windows-registry-key': 'stix2-sco2-icons/WindowsRegistryKey-Round.png',
    'x509-certificate': 'stix2-sco2-icons/X509Certificate-Round.png',
    'jarm': 'stix2-sco2-icons/Software-Round.png',
    
    // Relationships & Meta
    'relationship': 'stix2-relationship-icons-png/relationship-round-flat-300-dpi.png',
    'sighting': 'stix2-relationship-icons-png/sighting-round-flat-300-dpi.png',
    'bundle': 'stix2-meta-icons-png/bundle-round-flat-300-dpi.png',
    'marking-definition': 'stix2-sco2-icons/MarkingDefinition-Round.png',
    'language-content': 'stix2-meta-icons-png/language-round-flat-300-dpi.png'
};

let isFullScreenListenerAttached = false;

export const GraphManager = {
    initGraph: (actions) => {
        GraphManager.registerExtensions();

        if (state.cy) state.cy.destroy();
        const cyContainer = document.getElementById('cy');
        if (!cyContainer) return;

        const algoInput = document.getElementById('layoutAlgo');
        if (algoInput) {
            algoInput.value = 'cola';
            Array.from(algoInput.options).forEach(opt => {
                opt.selected = (opt.value === 'cola');
            });
        }

        state.cy = cytoscape({
            container: cyContainer,
            elements: GraphManager.getGraphElements(),
            style: GraphManager.getGraphStyle(),
            layout: GraphManager.getLayoutConfig()
        });

        state.cy.one('layoutstop', function(){
            state.cy.center();
            state.cy.zoom(1.5);
            state.cy.emit('zoom');
        });

        state.cy.on('tap', 'node', function(evt){
            if (state.connectionSource) {
                 actions.openRelationshipModal(state.connectionSource, evt.target.id());
            } else {
                 GraphManager.showNodeDetails(evt.target.data('raw'));
            }
        });

        state.cy.on('zoom', function(){
            const z = state.cy.zoom();
            const zoomSlider = document.getElementById('zoomSlider');
            const zoomVal = document.getElementById('zoomVal');
            if (zoomSlider) zoomSlider.value = z;
            if (zoomVal) zoomVal.innerText = z.toFixed(1) + 'x';
        });

        state.cy.cxtmenu({
            selector: 'node',
            commands: [
                {
                    content: '<span class="bi bi-arrows-expand"></span> Auto',
                    select: function(ele){ actions.preparePivot(ele.id(), true); }
                },
                {
                    content: '<span class="bi bi-list-check"></span> Pivot...',
                    select: function(ele){ actions.preparePivot(ele.id(), false); }
                },
                {
                     content: '<span class="bi bi-pencil-square"></span> Edit',
                     select: function(ele){ actions.editObject(ele.data('raw')); }
                },
                {
                     content: '<span class="bi bi-share"></span> Connect',
                     select: function(ele){ actions.startConnection(ele.id()); }
                },
                {
                    content: '<span class="bi bi-trash text-danger"></span> Remove',
                    select: function(ele){ GraphManager.removeNode(ele); }
                }
            ],
            fillColor: 'rgba(0, 0, 0, 0.75)',
            activeFillColor: 'rgba(13, 110, 253, 0.75)',
            activePadding: 10, 
            indicatorSize: 20, 
            separatorWidth: 2, 
            spotlightPadding: 3,
            minSpotlightRadius: 20,
            maxSpotlightRadius: 30,
            openMenuEvents: 'cxttapstart taphold',
            itemColor: 'white',
            itemTextShadowColor: 'transparent',
            zIndex: 9999
        });

        state.cy.cxtmenu({
            selector: 'edge',
            commands: [
                {
                    content: '<span class="bi bi-pencil-square"></span> Edit',
                    select: function(ele){ actions.editRelationship(ele.data('raw')); }
                },
                {
                    content: '<span class="bi bi-trash text-danger"></span> Delete',
                    select: function(ele){ GraphManager.removeEdge(ele); }
                }
            ],
            fillColor: 'rgba(0, 0, 0, 0.75)',
            activeFillColor: 'rgba(13, 110, 253, 0.75)',
        });
        
        if (!isFullScreenListenerAttached) {
            document.addEventListener('fullscreenchange', GraphManager.handleFullScreenChange);
            isFullScreenListenerAttached = true;
        }

        GraphManager.generateLegend();
    },

    registerExtensions: () => {
        try {
            if (typeof cytoscape === 'function') {
                if (window.cytoscapeCola) cytoscape.use(window.cytoscapeCola);
                if (window.cytoscapeKlay) cytoscape.use(window.cytoscapeKlay);
                if (window.cytoscapeDagre) cytoscape.use(window.cytoscapeDagre);
            }
        } catch (e) {
            console.warn("Huntsman: Error registering graph extensions. Layouts may fail.", e);
        }
    },

    handleFullScreenChange: () => {
        const container = document.getElementById('graph-container');
        const header = container ? container.querySelector('.card-header') : null;
        const cyDiv = document.getElementById('cy');
        
        if (document.fullscreenElement) {
            if (header) header.style.display = 'none';
            if (cyDiv) cyDiv.style.height = '100vh';
        } else {
            if (header) header.style.display = ''; 
            if (cyDiv) cyDiv.style.height = '700px';
        }

        setTimeout(() => {
            if (state.cy) {
                state.cy.resize();
                state.cy.fit();
            }
        }, 100);
    },

    updateGraph: () => {
        if(!state.cy) return;
        state.cy.json({ elements: GraphManager.getGraphElements() });
        GraphManager.updateLayout(); 
    },

    getGraphId: (obj) => {
        if (obj.type === 'relationship') return obj.id; 
        const val = obj.value || obj.name || obj.id;
        return `${obj.type}:${val}`;
    },

    getGraphElements: () => {
        const elements = [];
        state.stixObjects.forEach((obj, key) => {
            if (obj.type === 'relationship') {
                const sourceObj = Array.from(state.stixObjects.values()).find(o => o.id === obj.source_ref);
                const targetObj = Array.from(state.stixObjects.values()).find(o => o.id === obj.target_ref);
                if (sourceObj && targetObj) {
                    elements.push({
                        data: {
                            id: obj.id,
                            source: GraphManager.getGraphId(sourceObj),
                            target: GraphManager.getGraphId(targetObj),
                            label: obj.relationship_type,
                            raw: obj
                        }
                    });
                }
            } else {
                let label = obj.name || obj.value || obj.id;
                let isMatch = false;
                let isReport = (obj.type === 'report');
                let icon = null;

                if ((obj.value && state.correlationMatches[obj.value]) || 
                    (obj.name && state.correlationMatches[obj.name])) {
                    isMatch = true;
                    label += " [MATCH]";
                }
                
                let bgColor = TYPE_COLORS[obj.type] || TYPE_COLORS['default'];
                if (isMatch) bgColor = '#dc3545'; 
                
                if (ICON_MAP[obj.type]) {
                    icon = ICON_BASE_PATH + ICON_MAP[obj.type];
                }

                let classes = [obj.type];
                if (isMatch) classes.push('match');
                if (isReport) classes.push('report');

                elements.push({
                    data: { 
                        id: key, 
                        label: label, 
                        type: obj.type, 
                        bgColor: bgColor, 
                        icon: icon,
                        raw: obj 
                    },
                    classes: classes.join(' ')
                });
            }
        });
        return elements;
    },

    getGraphStyle: () => {
        return [
            {
                selector: 'node',
                style: {
                    'label': 'data(label)',
                    'color': '#333',
                    'font-size': '10px',
                    'text-valign': 'bottom',
                    'text-halign': 'center',
                    'text-margin-y': 4,
                    'width': '50px',
                    'height': '50px',
                    'background-color': 'data(bgColor)',
                    'background-opacity': 0.2,
                    'border-width': 0,
                    'text-wrap': 'wrap',
                    'text-max-width': '100px'
                }
            },
            {
                selector: 'node[icon]',
                style: {
                    'background-image': 'data(icon)',
                    'background-fit': 'cover',
                    'background-opacity': 0 
                }
            },
            { 
                selector: '.match', 
                style: { 
                    'border-width': 3, 
                    'border-color': '#dc3545',
                    'width': '60px',
                    'height': '60px',
                    'background-opacity': 0.1
                } 
            },
            {
                selector: 'edge',
                style: {
                    'width': 1.5,
                    'line-color': '#adb5bd',
                    'target-arrow-color': '#adb5bd',
                    'target-arrow-shape': 'triangle',
                    'curve-style': 'bezier',
                    'label': 'data(label)',
                    'font-size': '8px',
                    'text-rotation': 'autorotate',
                    'text-background-color': '#ffffff',
                    'text-background-opacity': 1,
                    'text-background-padding': 2
                }
            }
        ];
    },

    getLayoutConfig: () => {
        const algoInput = document.getElementById('layoutAlgo');
        const repulsionInput = document.getElementById('nodeRepulsion');
        const lengthInput = document.getElementById('edgeLength');

        const algo = (algoInput && algoInput.value) ? algoInput.value : 'cola';
        const repulsion = repulsionInput ? parseInt(repulsionInput.value) : 50000;
        const length = lengthInput ? parseInt(lengthInput.value) : 250;

        switch (algo) {
            case 'cola':
            default: 
                return {
                    name: 'cola',
                    animate: true,
                    refresh: 1,
                    maxSimulationTime: 4000,
                    nodeSpacing: function(node) { return repulsion / 500; },
                    edgeLength: length,
                    randomize: false,
                    fit: false
                };

            case 'klay':
                return {
                    name: 'klay',
                    animate: true,
                    klay: {
                        spacing: repulsion / 100,
                        edgeSpacingFactor: 0.5,
                        inLayerSpacingFactor: 1.5,
                        layoutHierarchy: true
                    },
                    fit: false
                };

            case 'dagre':
                return {
                    name: 'dagre',
                    rankDir: 'TB',
                    rankSep: length,
                    nodeSep: repulsion / 100,
                    animate: true,
                    fit: false
                };

            case 'grid':
                return {
                    name: 'grid',
                    animate: true,
                    spacingFactor: repulsion / 1000,
                    fit: false
                };

            case 'cose':
                return {
                    name: 'cose',
                    animate: true,
                    nodeRepulsion: function(node) { return repulsion; },
                    idealEdgeLength: function(edge) { return length; },
                    gravity: 1,
                    numIter: 1000,
                    nodeDimensionsIncludeLabels: true,
                    fit: false
                };
        }
    },

    updateLayout: () => {
        if (!state.cy) return;
        const layout = state.cy.layout(GraphManager.getLayoutConfig());
        layout.one('layoutstop', () => {
             state.cy.center();
        });
        layout.run();
    },

    setZoom: (val) => {
        if(!state.cy) return;
        const level = parseFloat(val);
        state.cy.zoom({
            level: level,
            renderedPosition: { x: state.cy.width() / 2, y: state.cy.height() / 2 }
        });
        const zoomVal = document.getElementById('zoomVal');
        if (zoomVal) zoomVal.innerText = level.toFixed(1) + 'x';
    },

    removeNode: (ele) => {
        const key = ele.id();
        if (state.stixObjects.has(key)) {
            const connectedEdges = state.cy.edges(`[source = "${key}"], [target = "${key}"]`);
            connectedEdges.forEach(edge => {
                if (state.stixObjects.has(edge.id())) {
                    state.stixObjects.delete(edge.id());
                }
            });

            state.stixObjects.delete(key);
            state.cy.remove(ele);
            GraphManager.updateGraph();
        }
    },

    removeEdge: (ele) => {
        const key = ele.id();
        if (state.stixObjects.has(key)) {
            state.stixObjects.delete(key);
            state.cy.remove(ele);
        }
    },
    
    toggleFullScreen: () => {
        const elem = document.getElementById("graph-container");
        if (!elem) return;
        
        if (!document.fullscreenElement) {
            elem.requestFullscreen()
                .catch(err => alert(`Error: ${err.message}`));
        } else {
            document.exitFullscreen();
        }
    },

    exportGraph: () => {
        if(!state.cy) return;
        const png64 = state.cy.png({ full: true, output: 'base64' });
        const link = document.createElement('a');
        link.download = 'huntsman-graph.png';
        link.href = 'data:image/png;base64,' + png64;
        link.click();
    },

    exportBundle: () => {
        if (state.stixObjects.size === 0) return alert("No objects to export.");
        
        const objects = Array.from(state.stixObjects.values());
        const uuid = crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2, 15);
        
        const bundle = {
            type: "bundle",
            id: `bundle--${uuid}`,
            objects: objects,
            spec_version: "2.1"
        };
        
        const jsonStr = JSON.stringify(bundle, null, 2);
        const blob = new Blob([jsonStr], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        
        const link = document.createElement('a');
        link.download = `huntsman_bundle_${uuid.substring(0,8)}.json`;
        link.href = url;
        link.click();
        
        URL.revokeObjectURL(url);
    },

    generateLegend: () => {
        const legendContainer = document.getElementById('legend-list');
        if (!legendContainer) return;
        legendContainer.innerHTML = '';
        
        const types = new Set();
        state.stixObjects.forEach(obj => {
            if (obj.type !== 'relationship') types.add(obj.type);
        });

        if (types.size === 0) {
            legendContainer.innerHTML = '<small class="text-muted">No data</small>';
            return;
        }

        Array.from(types).sort().forEach(type => {
            const color = TYPE_COLORS[type] || TYPE_COLORS['default'];
            const isChecked = !state.hiddenTypes.has(type);
            const div = document.createElement('div');
            div.className = 'legend-item';
            
            let iconHtml = '';
            if (ICON_MAP[type]) {
                 iconHtml = `<img src="${ICON_BASE_PATH + ICON_MAP[type]}" width="16" height="16" class="me-2">`;
            } else {
                 iconHtml = `<div class="legend-color-box" style="background-color: ${color};"></div>`;
            }

            div.innerHTML = `
                <div class="d-flex align-items-center">
                    ${iconHtml}
                    <input class="form-check-input me-2" type="checkbox" ${isChecked ? 'checked' : ''}>
                    <span class="text-capitalize">${type}</span>
                </div>
            `;
            div.querySelector('input').addEventListener('change', (e) => {
                if (e.target.checked) {
                    state.hiddenTypes.delete(type);
                    state.cy.nodes(`.${type}`).style('display', 'element');
                } else {
                    state.hiddenTypes.add(type);
                    state.cy.nodes(`.${type}`).style('display', 'none');
                }
            });
            legendContainer.appendChild(div);
        });
    },

    showNodeDetails: (stixObject) => {
        const panel = document.getElementById('node-details-panel');
        const content = document.getElementById('node-json');
        if (!panel || !content) return;

        panel.classList.remove('d-none');
        
        const jsonStr = JSON.stringify(stixObject, null, 2);
        content.innerHTML = jsonStr.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
            let cls = 'json-val';
            if (/^"/.test(match)) {
                if (/:$/.test(match)) {
                    cls = 'json-key';
                } else {
                    cls = 'json-str';
                }
            }
            return '<span class="' + cls + '">' + match + '</span>';
        });
    },

    hideNodeDetails: () => {
        const panel = document.getElementById('node-details-panel');
        if (panel) panel.classList.add('d-none');
    }
};
