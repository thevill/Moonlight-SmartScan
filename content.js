let currentWarning = null;

function normalizeUrl(url) {
    try {
        const urlObj = new URL(url);
        let normalized = `${urlObj.protocol}//${urlObj.hostname}${urlObj.pathname}`.replace(/\/$/, '');
        return normalized.toLowerCase();
    } catch {
        return url;
    }
}

function checkAndDisplayWarning() {
    const url = normalizeUrl(window.location.href);
    const cacheKey = `result_${url}`;

    chrome.storage.local.get([cacheKey], (data) => {
        const results = data[cacheKey] || {};
        const isMalicious = Object.values(results).some(r => r.verdict === 'Malicious');

        if (currentWarning) {
            currentWarning.remove();
            currentWarning = null;
        }

        if (isMalicious) {
            createWarningBanner();
        }
    });
}

function createWarningBanner() {
    const shadowHost = document.createElement('div');
    const shadowRoot = shadowHost.attachShadow({ mode: 'open' });
    currentWarning = shadowHost;

    // Create style element
    const style = document.createElement('style');
    style.textContent = `
        .areumsec-warning {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            background-color: #ff3d00;
            color: white;
            z-index: 2147483647;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            transform: translateY(0);
            transition: transform 0.3s ease;
        }
        .warning-content {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 12px 20px;
            max-width: 1200px;
            margin: 0 auto;
        }
        .icon {
            font-size: 20px;
            margin-right: 12px;
        }
        .message {
            font-size: 14px;
            margin-right: 20px;
            flex-grow: 1;
            text-align: center;
        }
        .dismiss-button {
            background: rgba(255, 255, 255, 0.2);
            border: 1px solid rgba(255, 255, 255, 0.4);
            color: white;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            font-weight: 600;
            transition: background 0.2s;
        }
        .dismiss-button:hover {
            background: rgba(255, 255, 255, 0.3);
        }
    `;

    // Create warning banner element
    const warning = document.createElement('div');
    warning.className = 'areumsec-warning';
    warning.innerHTML = `
        <div class="warning-content">
            <span class="icon">⚠️</span>
            <span class="message"><strong>Warning:</strong> This website has been flagged as potentially malicious by Moonlight SmartScan.</span>
            <button class="dismiss-button">Dismiss</button>
        </div>
    `;

    shadowRoot.appendChild(style);
    shadowRoot.appendChild(warning);
    document.body.prepend(shadowHost);

    warning.querySelector('.dismiss-button').onclick = () => {
        shadowHost.remove();
        currentWarning = null;
    };
}

// Throttle updates
let lastCheck = 0;
const throttleCheck = () => {
    const now = Date.now();
    if (now - lastCheck > 1000) {
        lastCheck = now;
        checkAndDisplayWarning();
    }
};

// Initial check
throttleCheck();

// Listen for updates from background
chrome.runtime.onMessage.addListener((message) => {
    if (message.type === 'safetyUpdate') {
        throttleCheck();
    }
});