
// Watch-Sec Mail Interceptor - Content Script

const BACKEND_URL = "http://localhost:8000";
// For now, hardcode API Key or fetch from local storage if managed.
// In a real enterprise deployment, this would be injected via Managed Storage Policy.
const TENANT_API_KEY = "e7cdae55-2e7e-467a-bdc5-3cbf5d321368"; // Correct Key
const AGENT_ID = "AGENT-CHROME-EXT"; // Placeholder

console.log("[Watch-Sec] Mail Interceptor Loaded.");

// Detect Platform
const isGmail = window.location.hostname.includes("google.com");
const isOutlook = window.location.hostname.includes("outlook");

document.addEventListener("click", async (e) => {
    // Heuristic: Check if clicked element is a "Send" button
    const target = e.target;
    // Gmail Send Button usually has role="button" and text "Send" or aria-label containing Send
    // Outlook Send Button usually has title="Send" or text "Send"

    let isSendClick = false;

    if (isGmail) {
        if (target.innerText === "Send" && target.getAttribute("role") === "button") isSendClick = true;
        if (target.getAttribute("aria-label")?.startsWith("Send")) isSendClick = true;
        // Search up tree for button
        if (!isSendClick && target.closest('[role="button"][aria-label*="Send"]')) isSendClick = true;
    } else if (isOutlook) {
        if (target.getAttribute("title") === "Send (Ctrl+Enter)") isSendClick = true;
        if (target.innerText === "Send") isSendClick = true;
        if (!isSendClick && target.closest('button[title="Send (Ctrl+Enter)"]')) isSendClick = true;
    }

    if (isSendClick) {
        console.log("[Watch-Sec] Send Click Detected! Capturing...");
        // Wait briefly for any final validation (or capture immediately)
        // We capture immediately before the window closes
        captureEmail();
    }
}, true); // Capture phase to ensure we get it early

function captureEmail() {
    let to = [];
    let subject = "";
    let body = "";

    if (isGmail) {
        // Recipient
        // Gmail uses "vT" or name="to" hidden inputs, or chips
        // Simple heuristic: Look for `email` attribute in chips or name="to"
        document.querySelectorAll('input[name="to"]').forEach(i => to.push(i.value));
        document.querySelectorAll('div[data-hovercard-id]').forEach(d => {
            const email = d.getAttribute("data-hovercard-id");
            if (email && email.includes("@")) to.push(email);
        });

        // Subject
        const subjInput = document.querySelector('input[name="subjectbox"]');
        if (subjInput) subject = subjInput.value;

        // Body
        const bodyDiv = document.querySelector('div[aria-label="Message Body"]');
        if (bodyDiv) body = bodyDiv.innerText;

    } else if (isOutlook) {
        // Improve Outlook Logic
        console.log("[Watch-Sec] Scrapping Outlook Web...");

        // Subject: Usually input[aria-label="Add a subject"] or similar
        const subjInputs = document.querySelectorAll('input');
        subjInputs.forEach(i => {
            const lbl = i.getAttribute('aria-label') || "";
            if (lbl.includes("Subject") || i.placeholder.includes("Subject")) subject = i.value;
        });

        // Body: ContentEditable div
        const bodyDivs = document.querySelectorAll('div[contenteditable="true"]');
        bodyDivs.forEach(d => {
            const lbl = d.getAttribute('aria-label') || "";
            if (lbl.toLowerCase().includes("body") || d.getAttribute('role') === 'textbox') {
                body = d.innerText;
            }
        });

        // To: Chips in container
        // Heuristic: Look for spans/divs with email-like text inside the "To" area
        // This is hard, defaulting to "Unknown" if not found is acceptable for PoC
        if (to.length === 0) to.push("(Outlook Web Recipient)");
    }

    const recipient = [...new Set(to)].join("; ") || "Unknown/Bcc";

    const payload = {
        AgentId: AGENT_ID,
        TenantApiKey: TENANT_API_KEY,
        Sender: "BrowserUser",
        Recipient: recipient,
        Subject: subject || "(No Subject)",
        BodyPreview: body.substring(0, 500),
        HasAttachments: false,
        AttachmentNames: "",
        Timestamp: new Date().toISOString()
    };

    console.log("[Watch-Sec] Payload:", payload);
    sendToBackend(payload);
}

function sendToBackend(payload) {
    fetch(`${BACKEND_URL}/api/mail`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
    })
        .then(r => console.log("[Watch-Sec] Sent Status:", r.status))
        .catch(e => console.error("[Watch-Sec] Send Error:", e));
}
