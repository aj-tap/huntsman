export const TYPE_COLORS = {
    // SDOs
    'report': '#343a40',
    'attack-pattern': '#dc3545',
    'campaign': '#fd7e14',
    'course-of-action': '#28a745',
    'identity': '#6f42c1',
    'indicator': '#d63384',
    'intrusion-set': '#fd7e14',
    'malware': '#dc3545',
    'observed-data': '#17a2b8',
    'threat-actor': '#6610f2',
    'tool': '#007bff',
    'vulnerability': '#dc3545',

    // Observables
    'artifact': '#6c757d',
    'autonomous-system': '#6610f2',
    'directory': '#ffc107',
    'domain-name': '#28a745',
    'email-addr': '#fd7e14',
    'email-message': '#ffc107',
    'file': '#ffc107',
    'ipv4-addr': '#007bff',
    'ipv6-addr': '#0056b3',
    'mac-addr': '#17a2b8',
    'mutex': '#e83e8c',
    'network-traffic': '#20c997',
    'process': '#e83e8c',
    'software': '#6f42c1',
    'url': '#17a2b8',
    'user-account': '#e83e8c',
    'windows-registry-key': '#6f42c1',
    'x509-certificate': '#20c997',

    'default': '#6c757d'
};

export function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

export function showToast(msg) {
    const toastBody = document.getElementById('toast-message');
    if (toastBody) toastBody.textContent = msg;
    const toastEl = document.getElementById('liveToast');
    if (toastEl) new bootstrap.Toast(toastEl).show();
}