const PYTHON_BRIDGE_URL = "http://127.0.0.1:8765/widevineproxy2";

function sanitizeBridgeUrl(value) {
    if (!value || typeof value !== "string")
        return null;

    try {
        const url = new URL(value);
        url.search = "";
        url.hash = "";
        return url.toString();
    } catch (e) {
        return null;
    }
}

function buildPythonBridgePayload(record) {
    const manifests = Array.isArray(record?.manifests)
        ? record.manifests.map((manifest) => ({
            type: manifest?.type ?? null,
            url: sanitizeBridgeUrl(manifest?.url),
            timestamp: manifest?.timestamp ?? null
        }))
        : [];

    return {
        event: "widevineproxy2_capture",
        timestamp: record?.timestamp ?? Date.now(),
        drm_type: record?.type ?? null,
        title: record?.title ?? null,
        page_url: sanitizeBridgeUrl(record?.url),
        manifests: manifests,
        key_count: Array.isArray(record?.keys) ? record.keys.length : 0,
        has_pssh: !!record?.pssh_data
    };
}

async function sendToPythonBridge(record) {
    try {
        const response = await fetch(PYTHON_BRIDGE_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(buildPythonBridgePayload(record)),
            cache: "no-store"
        });

        if (!response.ok) {
            console.debug("[WVP2 Python Bridge] Receiver returned", response.status);
        }
    } catch (e) {
        // The local receiver is optional. Capturing should continue normally when it is not running.
        console.debug("[WVP2 Python Bridge] Receiver unavailable");
    }
}

chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName !== "local")
        return;

    for (const { oldValue, newValue } of Object.values(changes)) {
        const isNewCapture =
            oldValue === undefined &&
            newValue &&
            typeof newValue === "object" &&
            typeof newValue.type === "string" &&
            typeof newValue.timestamp === "number";

        if (isNewCapture) {
            sendToPythonBridge(newValue);
        }
    }
});
