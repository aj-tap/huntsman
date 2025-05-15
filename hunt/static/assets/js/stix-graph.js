import { getCookie } from './utils.js';

let graphInstance = null;  // Global variable to store the graph instance
let initialData = null; // Store the initial data

async function fetchStixResults(stixId) {
    const csrftoken = getCookie('csrftoken');
    try {
        const response = await fetch('/api/tasks/retrieve-stix/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrftoken
            },
            body: JSON.stringify({ stix_id: stixId })
        });

        if (response.ok) {
            const data = await response.json();
            window.stixData = data;  // Save data globally
            initialData = data; // Store the initial data

            if (window.stixview) {
                const graphContainer = document.getElementById('stix-graph');

                graphInstance = window.stixview.init(graphContainer, (instance) => {
                    // Hide all objects except reports by default
                    hideAllObjectsExceptReportsByDefault(data.objects, instance);
                    instance.loadData(data);
                    createLegendButtons(data.objects);  // Generate toggle buttons
                }, (instance) => {
                    console.log("Graph Loaded", instance);

                    // Store the instance globally for easy access
                    graphInstance = instance;

                    document.getElementById('layout-select').addEventListener('change', function (e) {
                        graphInstance.runLayout(e.target.value);
                        updateHiddenObjects();  // Apply hidden objects when layout changes
                    });

                    document.getElementById('fit-graph').addEventListener('click', function () {
                        graphInstance.fit();
                    });
                });
            } else {
                console.error("stixview is not available.");
            }
        } else {
            console.error('Error fetching STIX results:', response);
            document.getElementById('stixResults').innerHTML = '<p>No STIX results were found. No information on the IOC was found from gathered sources.</p>';
        }
    } catch (error) {
        console.error('Error fetching STIX results:', error);
        document.getElementById('stixResults').innerHTML = '<p>No STIX results were found. No information on the IOC was found from gathered sources.</p>';
    }
}

// Create Buttons for Each Object Type
function createLegendButtons(objects) {
    const legendContainer = document.getElementById('legend-container');
    if (!legendContainer) return;

    legendContainer.innerHTML = '';

    const types = [...new Set(objects.map(obj => obj.type))]; // Unique object types

    types.forEach(type => {
        const button = document.createElement('button');
        button.className = 'btn btn-sm btn-outline-primary';
        button.textContent = type;
        button.dataset.type = type;
        button.style.marginRight = '5px';
        button.style.marginBottom = '5px';
        legendContainer.appendChild(button);

        button.addEventListener('click', function () {
            toggleObjectVisibility(this, objects);
        });
        // Set the button state based on the initial visibility
        const graphContainer = document.getElementById('stix-graph');
        const currentHiddenObjects = new Set(
            (graphContainer.getAttribute('data-hidden-objects') || '').split(',').filter(Boolean)
        );
        const objectIds = objects.filter(obj => obj.type === type).map(obj => obj.id);
        if (objectIds.every(id => currentHiddenObjects.has(id))) {
            button.classList.remove('btn-outline-primary');
            button.classList.add('btn-outline-secondary');
        }
    });
}

// Toggle Object Visibility
function toggleObjectVisibility(button, objects) {
    const graphContainer = document.getElementById('stix-graph');
    const objectType = button.dataset.type;

    // Get current hidden objects from attribute
    const currentHiddenObjects = new Set(
        (graphContainer.getAttribute('data-hidden-objects') || '').split(',').filter(Boolean)
    );

    const objectIds = objects.filter(obj => obj.type === objectType).map(obj => obj.id);

    if (objectIds.every(id => currentHiddenObjects.has(id))) {
        // Unhide objects if all are hidden
        objectIds.forEach(id => currentHiddenObjects.delete(id));
        button.classList.remove('btn-outline-secondary');
        button.classList.add('btn-outline-primary');
    } else {
        // Hide objects if not all are hidden
        objectIds.forEach(id => currentHiddenObjects.add(id));
        button.classList.remove('btn-outline-primary');
        button.classList.add('btn-outline-secondary');
    }

    // Update the attribute with new hidden objects
    graphContainer.setAttribute('data-hidden-objects', Array.from(currentHiddenObjects).join(','));

    // Apply the hidden objects to the graph instance and trigger a refresh
    if (graphInstance) {
        graphInstance.dataProps.hiddenObjects = Array.from(currentHiddenObjects);
        graphInstance.loadData(initialData);  // Use initialData here
    }

    console.log(`Updated hidden objects: ${graphContainer.getAttribute('data-hidden-objects')}`);
}

// Apply Hidden Objects to Graph When Layout Changes
function updateHiddenObjects() {
    const graphContainer = document.getElementById('stix-graph');
    const currentHiddenObjects = (graphContainer.getAttribute('data-hidden-objects') || '').split(',').filter(Boolean);

    if (graphInstance) {
        graphInstance.dataProps.hiddenObjects = currentHiddenObjects;
        graphInstance.loadData(initialData);  // Use initialData here
    }
}

// Initialize Graph Controls (Fit Button & Legend Container)
function initializeGraphControls() {
    const graphControls = document.getElementById('stix-graph-controls');
    graphControls.innerHTML = `
<div class="mb-3"> 
<p> Toggle visibility </p>
    <div id="legend-container" class="mb-3" style="background-color: #f9f9f9; border: 1px solid #ddd; padding: 15px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1);">
        <!-- Dynamic legend items will be added here -->
    </div>
    
    <button id="fit-graph" class="btn btn-primary btn-sm mb-2">Fit Graph</button>   
    <div class="d-flex align-items-center mb-3">
        <label for="layout-select" class="me-2 fw-bold">Select Layout:</label>
        <select id="layout-select" class="form-select form-select-sm w-auto">
            <optgroup label="Layouts">
                <option value="cose-bilkent">cose-bilkent</option>
                <option value="klay">klay</option>
                <option value="dagre">dagre</option>
                <option value="cise selected">cise</option>
                <option value="cola">cola</option>
            </optgroup>
        </select>
    </div>
</div>
    `;
}

// Function to hide all objects except report objects by default
function hideAllObjectsExceptReportsByDefault(objects, instance) {
    const graphContainer = document.getElementById('stix-graph');
    const reportObjects = objects.filter(obj => obj.type !== 'report');
    const reportObjectIds = reportObjects.map(obj => obj.id);

    // Get current hidden objects from attribute
    const currentHiddenObjects = new Set(
        (graphContainer.getAttribute('data-hidden-objects') || '').split(',').filter(Boolean)
    );

    // Add report object IDs to the set of hidden objects
    reportObjectIds.forEach(id => currentHiddenObjects.add(id));

    // Update the attribute with new hidden objects
    graphContainer.setAttribute('data-hidden-objects', Array.from(currentHiddenObjects).join(','));

    // Apply the hidden objects to the graph instance and trigger a refresh
    if (instance) {
        instance.dataProps.hiddenObjects = Array.from(currentHiddenObjects);
        instance.loadData(initialData); // Use initialData here
    }

    console.log(`All objects except report hidden by default: ${graphContainer.getAttribute('data-hidden-objects')}`);
}

export { fetchStixResults, initializeGraphControls };
