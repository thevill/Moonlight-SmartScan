document.addEventListener('DOMContentLoaded', () => {
    const loading = document.getElementById('loading');
    const resultsDiv = document.getElementById('results');
    const urlDisplay = document.getElementById('current-url');
    const apiHint = document.getElementById('apiHint');
    const optionsLink = document.querySelector('[data-options-link]');

    if (!loading || !resultsDiv || !urlDisplay || !apiHint || !optionsLink) return;

    // Check for API keys
    chrome.storage.sync.get(['vtApiKey', 'gsbApiKey'], (data) => {
        const hasVtApiKey = !!data.vtApiKey;
        const hasGsbApiKey = !!data.gsbApiKey;
        apiHint.style.display = (!hasVtApiKey && !hasGsbApiKey) ? 'block' : 'none';
    });

    optionsLink.addEventListener('click', () => chrome.runtime.openOptionsPage());

    // Get current tab URL
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (!tabs[0]?.url) {
            showError('Unable to access current tab');
            return;
        }

        const currentUrl = tabs[0].url;
        urlDisplay.textContent = currentUrl;

        // Initial fetch
        fetchResults(currentUrl);
    });

    function fetchResults(url) {
        loading.style.display = 'flex';
        resultsDiv.style.display = 'none';

        chrome.runtime.sendMessage({ action: "getResults", url }, (response) => {
            if (chrome.runtime.lastError) {
                console.error(chrome.runtime.lastError);
                showError('Communication error');
                return;
            }

            if (!response || Object.keys(response).length === 0) {
                triggerCheck(url);
            } else {
                displayResults(response);
            }
        });
    }

    function triggerCheck(url) {
        chrome.runtime.sendMessage({ action: "checkUrl", url }, (response) => {
            if (response && response.results) {
                displayResults(response.results);
            } else {
                showError(response?.message || 'Scan failed');
            }
        });
    }

    function displayResults(results) {
        loading.style.display = 'none';
        resultsDiv.style.display = 'block';
        resultsDiv.innerHTML = '';

        const { malicious, safe, error } = categorizeResults(results);

        if (malicious.length > 0) {
            resultsDiv.appendChild(createHeader('Threats Detected', 'warning-header'));
            malicious.forEach(r => resultsDiv.appendChild(createResultElement(r, 'malicious')));
        } else if (safe.length > 0) {
            resultsDiv.appendChild(createHeader('Safe', 'safe-header'));
            safe.forEach(r => resultsDiv.appendChild(createResultElement(r, 'safe')));
        } else if (error.length > 0) {
            resultsDiv.appendChild(createHeader('Errors', 'error-header'));
            error.forEach(r => resultsDiv.appendChild(createResultElement(r, 'error')));
        } else {
            resultsDiv.innerHTML = '<div class="result safe">No data available yet.</div>';
        }
    }

    function categorizeResults(results) {
        const malicious = [], safe = [], error = [];
        Object.entries(results).forEach(([source, data]) => {
            const item = { ...data, source: formatSourceName(source) };
            if (data.verdict === 'Malicious') malicious.push(item);
            else if (data.verdict === 'Safe') safe.push(item);
            else error.push(item);
        });
        return { malicious, safe, error };
    }

    function formatSourceName(key) {
        const names = {
            'local': 'Local Database',
            'virustotal': 'VirusTotal',
            'googleSafeBrowsing': 'Google Safe Browsing',
            'urlhaus': 'URLhaus',
            'phishingDB': 'PhishingDB'
        };
        return names[key] || key;
    }

    function createHeader(text, className) {
        const h3 = document.createElement('h3');
        h3.className = className;
        h3.textContent = text;
        return h3;
    }

    function createResultElement(result, type) {
        const div = document.createElement('div');
        div.className = `result ${type}`;

        const header = document.createElement('div');
        header.className = 'result-header';
        header.innerHTML = `<span class="service-name">${result.source}</span> <span class="verdict-badge ${type}">${result.verdict}</span>`;

        div.appendChild(header);

        if (result.details) {
            const details = document.createElement('div');
            details.className = 'details';
            if (typeof result.details === 'string') {
                details.textContent = result.details;
            } else {
                // Pretty print object details
                details.textContent = JSON.stringify(result.details, null, 2);
            }
            div.appendChild(details);
        }

        if (result.error) {
            const err = document.createElement('div');
            err.className = 'error-message';
            err.textContent = result.error;
            div.appendChild(err);
        }

        return div;
    }

    function showError(msg) {
        loading.style.display = 'none';
        resultsDiv.style.display = 'block';
        resultsDiv.innerHTML = `<div class="error-message">${msg}</div>`;
    }
});