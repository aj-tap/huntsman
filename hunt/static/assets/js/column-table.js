import { getCookie } from './utils.js'; // Assuming you'll create a utils.js for common functions

let lastValidData = null; // Store the last valid data here
let lastQuery = ''; // Store the last query used

async function fetchQueryResult(query) {
    const csrftoken = getCookie('csrftoken');
    const taskIds = localStorage.getItem('task_ids');
    const queryError = document.getElementById('queryError');
    lastQuery = query;
    try {
        const response = await fetch('/api/tasks/retrieve-threat-data/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrftoken
            },
            body: JSON.stringify({ task_ids: taskIds, custom_query: query })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(`HTTP error! status: ${response.status}. ${errorData.error}`);
        }
        const data = await response.json();

        lastValidData = data.results;
        return data.results;
    } catch (error) {
        console.error('Error fetching query results:', error);
        queryError.textContent = `Error: ${error.message}`;
        queryError.style.display = 'block';

        return null;
    }
}

function displayTable(data) {
    const table = document.getElementById('resultTable');
    const thead = table.querySelector('thead');
    const tbody = table.querySelector('tbody');
    const tableInfo = document.getElementById('tableInfo');
    const queryError = document.getElementById('queryError');
    const copyButton = document.getElementById('copyButton');
    closeColumnMenu();

    queryError.style.display = 'none';
    copyButton.style.display = 'none';

    if (data === null) {

        if (lastValidData) {
            data = lastValidData;
        } else {
            thead.innerHTML = '';
            tbody.innerHTML = '';
            table.style.display = 'none';
            tableInfo.innerHTML = '<p>No data available</p>';
            return;
        }
    }
    thead.innerHTML = '';
    tbody.innerHTML = '';
    table.style.display = 'none';
    if (!data || data.length === 0) {
        tableInfo.innerHTML = '<p>No data available</p>';
        return;
    }

    table.style.display = 'table';
    copyButton.style.display = 'block';
    const headers = Object.keys(data[0]);
    const headerRow = document.createElement('tr');
    headers.forEach((header, index) => {
        const th = document.createElement('th');
        th.textContent = header;
        th.style.cursor = 'pointer'; // Add cursor pointer
        th.setAttribute('data-column-index', index); // Store column index
        th.addEventListener('click', (event) => {
            showColumnMenu(event, header);
        });
        headerRow.appendChild(th);
    });
    thead.appendChild(headerRow);

    data.forEach(row => {
        const dataRow = document.createElement('tr');
        headers.forEach(header => {
            const td = document.createElement('td');
            let cellData = row[header];
            if (typeof cellData === 'object' && cellData !== null) {
                cellData = JSON.stringify(cellData, null, 2);
            }
            td.textContent = cellData ?? '';
            dataRow.appendChild(td);
        });
        tbody.appendChild(dataRow);
    });
    copyButton.addEventListener('click', () => {
        copyTableToClipboard(data, headers);
    });
}
function copyTableToClipboard(data, headers) {
    let reportContent = "";

    // Iterate over each row of data
    data.forEach(row => {
        headers.forEach(header => {
            let cellData = row[header];

            if (typeof cellData === 'object' && cellData !== null) {
                // If it's an object or array, convert it to a string format
                cellData = JSON.stringify(cellData).replace(/[\[\]"]+/g, ''); // Remove extra brackets and quotes
            }

            // Add the formatted row data as key: value
            reportContent += `${header}: ${cellData ?? ''}\n`;
        });

        // Add a separator for each row for better readability
        reportContent += '\n';
    });

    // Copy the formatted report to clipboard
    navigator.clipboard.writeText(reportContent)
        .then(() => {
            console.log("Table data copied to clipboard!");
        })
        .catch(err => {
            console.error('Failed to copy table data:', err);
        });
}

let sortDirection = {}; // to keep track of the current sorting direction.

function sortTable(columnIndex, data, order) {
    const headerName = Object.keys(data[0])[columnIndex];
    const table = document.getElementById('resultTable');
    const tbody = table.querySelector('tbody');
    // Determine sort direction

    const sortedData = data.sort((a, b) => {
        const aValue = a[headerName];
        const bValue = b[headerName];

        if (order === 'asc') {
            if (aValue < bValue) return -1;
            if (aValue > bValue) return 1;
        } else {
            if (aValue < bValue) return 1;
            if (aValue > bValue) return -1;
        }
        return 0;
    });

    // Rebuild the table body with the sorted data
    tbody.innerHTML = '';
    sortedData.forEach(row => {
        const dataRow = document.createElement('tr');
        Object.keys(row).forEach(header => {
            const td = document.createElement('td');
            let cellData = row[header];
            if (typeof cellData === 'object' && cellData !== null) {
                cellData = JSON.stringify(cellData, null, 2);
            }
            td.textContent = cellData ?? '';
            dataRow.appendChild(td);
        });
        tbody.appendChild(dataRow);
    });

}

function showColumnMenu(event, columnName) {
    event.preventDefault();
    event.stopPropagation();

    const menu = document.getElementById('columnActionMenu');
    menu.style.display = 'block';
    menu.style.left = `${event.pageX}px`;
    menu.style.top = `${event.pageY}px`;

    // Store the column name in the menu for actions
    menu.dataset.columnName = columnName;
    // Check if the dropdown is already attached
    if (!menu.dataset.eventListenersAdded) {
        // Attach event listeners
        menu.querySelector('.sort-asc').addEventListener('click', handleSortAsc);
        menu.querySelector('.sort-desc').addEventListener('click', handleSortDesc);
        menu.querySelector('.count-by').addEventListener('click', handleCountBy);
        menu.querySelector('.yield-value').addEventListener('click', handleYieldValue);

        // Set the flag to indicate event listeners have been attached
        menu.dataset.eventListenersAdded = 'true';
    }

}

function closeColumnMenu() {
    const menu = document.getElementById('columnActionMenu');
    menu.style.display = 'none';
}

function handleSortAsc(event) {
    event.preventDefault();
    const menu = document.getElementById('columnActionMenu');
    const columnIndex = Array.from(document.querySelectorAll('#resultTable th')).findIndex(th => th.textContent === menu.dataset.columnName);

    sortTable(columnIndex, lastValidData, 'asc');
    closeColumnMenu();
}

function handleSortDesc(event) {
    event.preventDefault();
    const menu = document.getElementById('columnActionMenu');
    const columnIndex = Array.from(document.querySelectorAll('#resultTable th')).findIndex(th => th.textContent === menu.dataset.columnName);
    sortTable(columnIndex, lastValidData, 'desc');
    closeColumnMenu();
}

function handleCountBy(event) {
    event.preventDefault();
    const menu = document.getElementById('columnActionMenu');
    const columnName = menu.dataset.columnName;
    const queryTextArea = document.getElementById('query');
    const currentQuery = queryTextArea.value.trim();

    // Add the count() by column to the current query
    let newQuery = '';
    if (!currentQuery) {
        newQuery = `count() by this["${columnName}"]`;
    } else {
        newQuery = `${currentQuery} | count() by this["${columnName}"]`;
    }

    queryTextArea.value = newQuery;

    // Trigger the form submit to execute the new query
    document.getElementById('queryForm').dispatchEvent(new Event('submit'));

    closeColumnMenu();
}
function handleYieldValue(event) {
    event.preventDefault();
    const menu = document.getElementById('columnActionMenu');
    const columnName = menu.dataset.columnName;
    const queryTextArea = document.getElementById('query');
    const currentQuery = queryTextArea.value.trim();

    let newQuery = '';
     if (!currentQuery) {
        newQuery = `yield this["${columnName}"]`;
    } else {
        // Check if there is a yield statement already
        const yieldIndex = currentQuery.indexOf('yield');
        if (yieldIndex !== -1) {
            // If a yield statement exists, append to it
            const existingYield = currentQuery.substring(yieldIndex + 6).trim(); // +6 to skip 'yield '
             if(existingYield){
                newQuery = `${currentQuery.substring(0, yieldIndex)} yield ${existingYield} | yield this["${columnName}"]`;
             }else{
                 newQuery = `${currentQuery} | yield this["${columnName}"]`;
             }
        }else{
               newQuery = `${currentQuery} | yield this["${columnName}"]`;
        }
       
    }
    
    queryTextArea.value = newQuery;
    document.getElementById('queryForm').dispatchEvent(new Event('submit'));
    closeColumnMenu();
}

// Close column menu when clicking outside
document.addEventListener('click', (event) => {
    const menu = document.getElementById('columnActionMenu');
    if (menu.style.display === 'block' && !menu.contains(event.target) && !document.querySelector('#resultTable th').contains(event.target)) {
        closeColumnMenu();
    }
});



export { fetchQueryResult, displayTable };
