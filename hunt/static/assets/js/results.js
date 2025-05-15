import { fetchStixResults, initializeGraphControls } from './stix-graph.js';
import { fetchQueryResult, displayTable } from './column-table.js';
import { getCookie } from './utils.js';

const DEFAULT_QUERY = `switch (
    case meta.analyzerName=="virustotal"=> {Source:meta.analyzerName, observable, Results:"VTScore: " + cast(rawData.data.attributes.last_analysis_stats, <string>), Link:"https://www.virustotal.com/gui/search/" + observable}
    case meta.analyzerName=="abuseipdb"=> {Source:meta.analyzerName, observable, Results:"Abuse Confidence Score: " + cast(rawData.data.abuseConfidenceScore, <string>), Link:"https://www.abuseipdb.com/check/" + observable}
    case meta.analyzerName=="alienvault"=> {Source:meta.analyzerName, observable, Results:"AlienVault Pulse Count: " + cast(rawData.pulse_info.count, <string>), Link: "https://otx.alienvault.com/browse/global/pulses?q=" + observable}
    case meta.analyzerName=="internetstormcast"=> {Source:meta.analyzerName, observable, Results:"Reported Attacks: " + cast(rawData.ip.attacks, <string>), Link: "https://isc.sans.edu/ipinfo/" + observable}
    case meta.analyzerName=="ipinfo"=> {Source:meta.analyzerName, observable, Results:"IPInfo: " + cast(rawData, <string>), Link:"https://ipinfo.io/"+ observable}
    case meta.analyzerName=="internetdb"=> {Source:meta.analyzerName, observable, Results:"InternetDB: " + cast(rawData.tags, <string>),  Link:"https://internetdb.shodan.io/" + observable }
    case meta.analyzerName=="shodan"=> {Source:meta.analyzerName, observable, Results:"Hostname: " + cast(rawData.hostnames, <string>) + ", ISP: " + cast(rawData.isp, <string>) + ", Ports: " +  cast(rawData.ports, <string>) + ", Tags: " +  cast(rawData.tags, <string>), Link: "https://www.shodan.io/host/" + observable}
    case meta.analyzerName=="crowdsec"=> {Source:meta.analyzerName, observable, Results:"Score: " + cast(rawData.scores.overall, <string>), Link: "https://app.crowdsec.net/cti/" + observable}
    case (meta.analyzerName=='threatfox' and rawData.query_status!="no_result") => {Source:meta.analyzerName, observable, Results:'Threatfox: ' + cast(rawData.data, <string>), Link: 'https://threatfox.abuse.ch/browse.php?search=ioc:' + observable}
    case (meta.analyzerName=='wildfire' and rawData.wildfire["get-verdict-info"].verdict=="0") => {Source:meta.analyzerName, observable, Results:'Wildfire Verdict: Benign', Link:'https://www.paloaltonetworks.com/network-security/wildfire'}
    case (meta.analyzerName=='wildfire' and rawData.wildfire["get-verdict-info"].verdict=="1") => {Source:meta.analyzerName, observable, Results:'Wildfire Verdict: Malware', Link:'https://www.paloaltonetworks.com/network-security/wildfire'}
    case (meta.analyzerName=='wildfire' and rawData.wildfire["get-verdict-info"].verdict=="2") => {Source:meta.analyzerName, observable, Results:'Wildfire Verdict: Grayware', Link:'https://www.paloaltonetworks.com/network-security/wildfire'}
    case (meta.analyzerName=='wildfire' and rawData.wildfire["get-verdict-info"].verdict=="4") => {Source:meta.analyzerName, observable, Results:'Wildfire Verdict: Phishing', Link:'https://www.paloaltonetworks.com/network-security/wildfire'}
    case (meta.analyzerName=='wildfire' and rawData.wildfire["get-verdict-info"].verdict=="5") => {Source:meta.analyzerName, observable, Results:'Wildfire Verdict: Command and Control', Link:'https://www.paloaltonetworks.com/network-security/wildfire'}
    case (meta.analyzerName=='wildfire' and rawData.wildfire["get-verdict-info"].verdict=="-100") => {Source:meta.analyzerName, observable, Results:'Wildfire Verdict: sample exists, but there is currently no verdict', Link:'https://www.paloaltonetworks.com/network-security/wildfire'}    
    case (meta.analyzerName=='wildfire' and rawData.wildfire["get-verdict-info"].verdict=="-102") => {Source:meta.analyzerName, observable, Results:'Wildfire Verdict: Unknown, cannot find sample record in wildfire DB', Link:'https://www.paloaltonetworks.com/network-security/wildfire'}
    case (meta.analyzerName=='malwarebazaar' and rawData.query_status=="ok" ) => {Source:meta.analyzerName, observable, Results:'Malware Bazaar:'+ cast(rawData.data, <string>), Link:'https://bazaar.abuse.ch/sample/'  + observable }
    case meta.analyzerName=="spurus" => {Source:meta.analyzerName, observable, Results:"" + cast(rawData.attribution, <string>), Link:"https://spur.us/context/" + observable}
    case meta.analyzerName=="proxycheckio" => {Source:meta.analyzerName, observable, Results:"" + cast(rawData, <string>), Link:"https://proxycheck.io/v2/" + observable}
) | Results!='null'`;

// Function to fetch and display detection results
async function fetchAndDisplayDetectionResults() {
    const detectionResultsContent = document.getElementById('detectionResultsContent');
    const detectionLoader = document.getElementById('detectionLoader');
    const detection_task_id = localStorage.getItem('detection_task_id');
    const csrftoken = getCookie('csrftoken');

    if (!detection_task_id) {
        detectionResultsContent.innerHTML = '<p class="text-danger">No detection task ID found.</p>';
        return;
    }

    // Show loader and clear content
    detectionLoader.style.display = 'block';
    detectionResultsContent.innerHTML = '';

    try {
        const response = await fetch('/api/tasks/retrieve-detections-result/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrftoken
            },
            body: JSON.stringify({ detection_id: detection_task_id })
        });

        if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);

        const data = await response.json();
        detectionLoader.style.display = 'none';

        if (data.error) {
            detectionResultsContent.innerHTML = `<p class="text-danger">Error: ${data.error}</p>`;
            return;
        }

        if (data.message) {
            detectionResultsContent.innerHTML = `<p>${data.message}</p>`;
            return;
        }

        if (!data.results || data.results.length === 0) {
            detectionResultsContent.innerHTML = '<p>No detection results found.</p>';
            return;
        }

        // Build the table directly
        let tableHTML = `
            <div class="table-responsive">
                <table class="table table-striped table-bordered align-middle">
                    <thead>
                        <tr>
                            <th>Rule Title</th>
                            <th>Description</th>
                            <th>Observables (Hits)</th>
                        </tr>
                    </thead>
                    <tbody>`;

        data.results.forEach(result => {
            tableHTML += `
                <tr>
                    <td><strong>${result.rule_title}</strong></td>
                    <td>${result.rule_description}</td>
                    <td>
                        <ul class="list-unstyled mb-0">` +
                            result.hits.map(hit => `<li> ${hit.observable}</li>`).join('') +
                        `</ul>
                    </td>
                </tr>`;
        });

        tableHTML += `</tbody></table></div>`;

        // Insert the table into the DOM
        detectionResultsContent.innerHTML = tableHTML;
    } catch (error) {
        console.error('Error fetching detection results:', error);
        detectionResultsContent.innerHTML = `<p class="text-danger">Error fetching detection results: ${error.message}</p>`;
        detectionLoader.style.display = 'none';
    }
}

window.addEventListener('load', async () => {
    const form = document.getElementById('queryForm');
    const queryTextArea = document.getElementById('query'); // Get the queryTextArea here
    const stixTaskId = localStorage.getItem('stix_task_id');
    const tableContainer = document.getElementById('resultTableContainer');

    initializeGraphControls();

    if (stixTaskId) {
        fetchStixResults(stixTaskId);
    } else {
        document.getElementById('stixResults').innerHTML = '<p>No STIX data available.</p>';
    }

    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        const query = queryTextArea.value;
        try {
            const queryResults = await fetchQueryResult(query);
            displayTable(queryResults);
        } catch (error) {
            console.error("Error fetching or displaying query results:", error);
            tableContainer.innerHTML = '<p>Error loading query data.</p>';
        }
    });

    try {
        queryTextArea.value = DEFAULT_QUERY;
        const initialData = await fetchQueryResult(DEFAULT_QUERY);
        displayTable(initialData);
    } catch (error) {
        console.error("Error fetching initial data:", error);
        tableContainer.innerHTML = '<p></p>';
    }

    // Fetch and display detection results
    fetchAndDisplayDetectionResults();
});