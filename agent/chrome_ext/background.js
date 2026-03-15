
try {
    importScripts('config.js');
} catch (e) {
    console.error("Config load failed", e);
}

// History Tracker
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url && (tab.url.startsWith('http') || tab.url.startsWith('https'))) {

        // Filter out internal/boring URLs?
        if (tab.url.includes("localhost") || tab.url.includes("127.0.0.1")) return;

        console.log(`[Watch-Sec] Visited: ${tab.url}`);

        const payload = {
            "AgentId": CONFIG.AGENT_ID,
            "TenantApiKey": CONFIG.TENANT_API_KEY,
            "ActivityType": "Web",
            "WindowTitle": tab.title || "No Title",
            "ProcessName": "Chrome/Edge",
            "Url": tab.url,
            "DurationSeconds": 0, // Event-based
            "IdleSeconds": 0,
            "Category": "Neutral", // Evaluation on backend?
            "ProductivityScore": 0,
            "Timestamp": new Date().toISOString()
        };

        sendToBackend(payload);
    }
});

function sendToBackend(payload) {
    if (!CONFIG.BACKEND_URL || CONFIG.BACKEND_URL.includes("monitorix.co.in") === false) {
        // Safety check or fallback?
    }

    fetch(`${CONFIG.BACKEND_URL}/api/events/activity`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
    }).catch(e => console.error("History Log Error", e));
}
