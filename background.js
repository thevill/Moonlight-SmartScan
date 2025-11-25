const ALARM_NAME = 'updateDatabases';
const CACHE_DURATION = 60 * 60 * 1000; // 1 hour for API results
const RATE_LIMIT = {
    virustotal: { max: 4, window: 60 * 1000 },
    googleSafeBrowsing: { max: 10000, window: 24 * 60 * 60 * 1000 }
};

// In-memory databases (loaded from storage)
let threatData = {
    urlhaus: new Set(),
    phishingDB: new Set(),
    loaded: false
};

// Rate limiting state
const requestCounts = {
    virustotal: { count: 0, lastReset: 0 },
    googleSafeBrowsing: { count: 0, lastReset: 0 }
};

// Pending checks to avoid duplicate processing
const pendingChecks = new Map(); // url -> Promise

// Initialize
chrome.runtime.onInstalled.addListener(() => {
    console.log('Extension installed/updated');
    chrome.alarms.create(ALARM_NAME, { periodInMinutes: 240 }); // Every 4 hours
    updateDatabases(); // Initial fetch
});

chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === ALARM_NAME) {
        updateDatabases();
    }
});

// Load databases on startup
loadThreatData();

function loadThreatData() {
    chrome.storage.local.get(['threatData_urlhaus', 'threatData_phishingDB'], (data) => {
        if (data.threatData_urlhaus) {
            threatData.urlhaus = new Set(data.threatData_urlhaus);
        }
        if (data.threatData_phishingDB) {
            threatData.phishingDB = new Set(data.threatData_phishingDB);
        }
        threatData.loaded = true;
        console.log(`Threat data loaded: ${threatData.urlhaus.size} URLhaus, ${threatData.phishingDB.size} PhishingDB`);
    });
}

async function updateDatabases() {
    console.log('Updating threat databases...');
    try {
        const [urlhaus, phishingDB] = await Promise.all([
            fetchUrlhaus(),
            fetchPhishingDB()
        ]);

        // Update in-memory
        threatData.urlhaus = urlhaus;
        threatData.phishingDB = phishingDB;
        threatData.loaded = true;

        // Save to storage
        await chrome.storage.local.set({
            threatData_urlhaus: Array.from(urlhaus),
            threatData_phishingDB: Array.from(phishingDB),
            lastUpdate: Date.now()
        });
        console.log('Threat databases updated successfully');
    } catch (e) {
        console.error('Failed to update threat databases:', e);
    }
}

async function fetchUrlhaus() {
    try {
        const response = await fetch('https://urlhaus.abuse.ch/downloads/text/', { signal: AbortSignal.timeout(30000) });
        if (!response.ok) throw new Error('Failed to fetch URLhaus');
        const text = await response.text();
        return new Set(text.split('\n')
            .filter(line => line && !line.startsWith('#'))
            .map(url => normalizeUrlWithoutProtocol(url)));
    } catch (e) {
        console.error('URLhaus fetch error:', e);
        return threatData.urlhaus; // Return existing on failure
    }
}

async function fetchPhishingDB() {
    const sources = [
        'https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/refs/heads/master/phishing-links-ACTIVE.txt',
        'https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/refs/heads/master/phishing-links-NEW-today.txt'
    ];

    const combined = new Set();
    for (const source of sources) {
        try {
            const response = await fetch(source, { signal: AbortSignal.timeout(15000) });
            if (!response.ok) continue;
            const text = await response.text();
            text.split('\n')
                .filter(line => line && !line.startsWith('#'))
                .forEach(url => combined.add(normalizeUrlWithoutProtocol(url)));
        } catch (e) {
            console.error(`PhishingDB source error (${source}):`, e);
        }
    }
    return combined.size > 0 ? combined : threatData.phishingDB;
}

// Message Handling
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "getResults") {
        handleGetResults(request.url).then(sendResponse);
        return true; // Async response
    }
    if (request.action === "checkUrl") {
        checkUrlSafety(request.url, true).then(results => {
            sendResponse({ status: 'success', results });
        }).catch(e => {
            sendResponse({ status: 'error', message: e.message });
        });
        return true;
    }
});

async function handleGetResults(url) {
    const normalizedUrl = normalizeUrl(url);
    const cacheKey = `result_${normalizedUrl}`;

    // Check cache first
    const cached = await chrome.storage.local.get(cacheKey);
    if (cached[cacheKey] && !isExpired(cached[cacheKey])) {
        return cached[cacheKey];
    }

    // If we are already checking this URL, wait for it
    if (pendingChecks.has(normalizedUrl)) {
        return await pendingChecks.get(normalizedUrl);
    }

    // Start a new check and wait for results
    const results = await checkUrlSafety(url, false);
    return results;
}

// Navigation Listeners - Use webNavigation for faster detection
chrome.webNavigation.onCommitted.addListener((details) => {
    if (details.frameId === 0 && details.url && details.url.startsWith('http')) {
        console.log('Navigation committed:', details.url);
        checkUrlSafety(details.url, false);
    }
});

// Fallback for tab updates (sometimes webNavigation misses things or for SPA)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'loading' && tab.url && tab.url.startsWith('http')) {
        // Start check early on loading
        checkUrlSafety(tab.url, false);
    }
});

chrome.tabs.onActivated.addListener(async (activeInfo) => {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab.url && tab.url.startsWith('http')) {
        handleGetResults(tab.url);
    }
});

// Core Safety Check Logic
async function checkUrlSafety(url, force = false) {
    const normalizedUrl = normalizeUrl(url);
    const cacheKey = `result_${normalizedUrl}`;

    if (pendingChecks.has(normalizedUrl)) {
        return pendingChecks.get(normalizedUrl);
    }

    const checkPromise = (async () => {
        try {
            // 1. Check Local Databases (Fastest - Sync check if loaded)
            if (threatData.loaded) {
                const localResults = checkLocalDatabases(normalizedUrl);
                if (localResults.verdict === 'Malicious') {
                    const finalResults = { local: localResults };
                    await saveResults(cacheKey, finalResults);
                    notifyIfMalicious(finalResults, url);
                    return finalResults;
                }
            }

            // 2. Check APIs (Slower)
            if (!force) {
                const cached = await chrome.storage.local.get(cacheKey);
                if (cached[cacheKey] && !isExpired(cached[cacheKey])) {
                    return cached[cacheKey];
                }
            }

            const apiResults = await checkApis(normalizedUrl);

            // Re-check local in case it loaded during API call
            let localResults = { verdict: 'Unknown', details: 'Database loading...' };
            if (threatData.loaded) {
                localResults = checkLocalDatabases(normalizedUrl);
            }

            const finalResults = { ...apiResults };
            if (localResults.verdict !== 'Unknown') {
                finalResults.local = localResults;
            }

            await saveResults(cacheKey, finalResults);
            notifyIfMalicious(finalResults, url);
            return finalResults;

        } catch (e) {
            console.error('Safety check failed:', e);
            return { error: { verdict: 'Error', error: e.message } };
        } finally {
            pendingChecks.delete(normalizedUrl);
        }
    })();

    pendingChecks.set(normalizedUrl, checkPromise);
    return checkPromise;
}

function checkLocalDatabases(url) {
    const cleanUrl = normalizeUrlWithoutProtocol(url);

    if (!threatData.loaded) {
        return { verdict: 'Unknown', details: 'Database loading...' };
    }

    if (threatData.urlhaus.has(cleanUrl)) {
        return { verdict: 'Malicious', source: 'URLhaus', details: 'Found in URLhaus database' };
    }
    if (threatData.phishingDB.has(cleanUrl)) {
        return { verdict: 'Malicious', source: 'PhishingDB', details: 'Found in PhishingDB' };
    }

    return { verdict: 'Safe', source: 'Local DB', details: 'Not found in local databases' };
}

async function checkApis(url) {
    const { vtApiKey, gsbApiKey } = await chrome.storage.sync.get(['vtApiKey', 'gsbApiKey']);
    const results = {};
    const now = Date.now();

    const checks = [];

    // VirusTotal
    if (vtApiKey && canRequest('virustotal')) {
        checks.push(checkVirusTotal(url, vtApiKey).then(res => {
            results.virustotal = { ...res, timestamp: now };
            incrementRequest('virustotal');
        }).catch(e => {
            results.virustotal = { verdict: 'Error', error: e.message, timestamp: now };
        }));
    }

    // Google Safe Browsing
    if (gsbApiKey && canRequest('googleSafeBrowsing')) {
        checks.push(checkGoogleSafeBrowsing(url, gsbApiKey).then(res => {
            results.googleSafeBrowsing = { ...res, timestamp: now };
            incrementRequest('googleSafeBrowsing');
        }).catch(e => {
            results.googleSafeBrowsing = { verdict: 'Error', error: e.message, timestamp: now };
        }));
    }

    await Promise.all(checks);
    return results;
}

function normalizeUrl(url) {
    try {
        const urlObj = new URL(url);
        let normalized = `${urlObj.protocol}//${urlObj.hostname}${urlObj.pathname}`.replace(/\/$/, '');
        return normalized.toLowerCase();
    } catch {
        return url;
    }
}

function normalizeUrlWithoutProtocol(url) {
    try {
        const urlObj = new URL(url);
        let normalized = `${urlObj.hostname}${urlObj.pathname}`.replace(/\/$/, '');
        return normalized.toLowerCase();
    } catch {
        return url;
    }
}

function isExpired(result) {
    if (!result) return true;
    const timestamp = Math.max(...Object.values(result).map(r => r.timestamp || 0));
    return (Date.now() - timestamp) > CACHE_DURATION;
}

function canRequest(service) {
    const now = Date.now();
    if (now - requestCounts[service].lastReset > RATE_LIMIT[service].window) {
        requestCounts[service].count = 0;
        requestCounts[service].lastReset = now;
    }
    return requestCounts[service].count < RATE_LIMIT[service].max;
}

function incrementRequest(service) {
    requestCounts[service].count++;
}

async function saveResults(key, results) {
    await chrome.storage.local.set({ [key]: results });

    // Notify all tabs about the update (content scripts will filter by their own URL)
    try {
        const tabs = await chrome.tabs.query({});
        if (tabs && tabs.length > 0) {
            tabs.forEach(tab => {
                if (tab.id && tab.url && tab.url.startsWith('http')) {
                    chrome.tabs.sendMessage(tab.id, { type: 'safetyUpdate', results }).catch(() => {
                        // Ignore errors for tabs without content script
                    });
                }
            });
        }
    } catch (e) {
        console.error('Error notifying tabs:', e);
    }
}

function notifyIfMalicious(results, url) {
    const maliciousSources = [];

    // Collect all sources that detected malicious content
    Object.entries(results).forEach(([source, data]) => {
        if (data.verdict === 'Malicious') {
            maliciousSources.push({
                name: formatSourceName(source),
                details: data.details
            });
        }
    });

    if (maliciousSources.length > 0) {
        try {
            const urlObj = new URL(url);
            const urlHostname = urlObj.hostname;

            // Build detailed message
            const sourceNames = maliciousSources.map(s => s.name).join(', ');
            const message = `⚠️ Threat detected by: ${sourceNames}\n\n🌐 URL: ${urlHostname}\n\n⛔ This site may contain malware, phishing, or other threats. Proceed with caution!`;

            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icon128.png',
                title: '🛡️ Moonlight SmartScan - Threat Detected!',
                message: message,
                priority: 2,
                requireInteraction: true
            });
        } catch (e) {
            console.error('Error creating notification:', e);
        }
    }
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

async function checkVirusTotal(url, apiKey) {
    const urlId = btoa(url).replace(/=/g, '');
    const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
        headers: { 'x-apikey': apiKey }
    });
    const data = await response.json();
    if (data.data) {
        const stats = data.data.attributes.last_analysis_stats;
        return {
            verdict: stats.malicious > 0 ? 'Malicious' : 'Safe',
            details: stats,
            source: 'VirusTotal'
        };
    }
    throw new Error('No data');
}

async function checkGoogleSafeBrowsing(url, apiKey) {
    const payload = {
        client: { clientId: 'moonlight-smartscan', clientVersion: '1.0.3' },
        threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url }]
        }
    };
    const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });
    const data = await response.json();
    return {
        verdict: data.matches?.length > 0 ? 'Malicious' : 'Safe',
        details: data.matches || { message: 'No threats detected' },
        source: 'Google Safe Browsing'
    };
}