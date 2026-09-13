const PYTHON_BRIDGE_BASE_URL = "http://127.0.0.1:8765";
const PYTHON_BRIDGE_URL = `${PYTHON_BRIDGE_BASE_URL}/widevineproxy2`;
const PYTHON_BRIDGE_TAB_JOB_PREFIX = "wvp2_python_bridge_job_";
const PYTHON_BRIDGE_JOB_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

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

function bridgeJobStorage() {
    // chrome.storage.session survives MV3 service-worker suspension but is
    // cleared when the browser session ends. Fall back to local for browsers
    // that do not expose session storage.
    return chrome.storage.session || chrome.storage.local;
}

function bridgeTabJobKey(tabId) {
    return `${PYTHON_BRIDGE_TAB_JOB_PREFIX}${tabId}`;
}

async function setBridgeJobForTab(tabId, jobId) {
    const key = bridgeTabJobKey(tabId);
    await bridgeJobStorage().set({ [key]: jobId });
}

async function getBridgeJobForTab(tabId) {
    const key = bridgeTabJobKey(tabId);
    const value = await bridgeJobStorage().get(key);
    return typeof value?.[key] === "string" ? value[key] : null;
}

async function clearBridgeJobForTab(tabId) {
    await bridgeJobStorage().remove(bridgeTabJobKey(tabId));
}

async function postBridgeJson(path, payload) {
    const response = await fetch(`${PYTHON_BRIDGE_BASE_URL}${path}`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(payload),
        cache: "no-store"
    });

    let body = null;
    try {
        body = await response.json();
    } catch (e) {
        // Keep the HTTP status as the authoritative result.
    }

    return { response, body };
}

async function attachBridgeJobToTab(jobId, tabId) {
    // Persist the mapping first so MV3 service-worker suspension cannot lose it.
    await setBridgeJobForTab(tabId, jobId);

    try {
        const { response, body } = await postBridgeJson(
            `/jobs/${encodeURIComponent(jobId)}/attached`,
            { tab_id: tabId }
        );

        if (!response.ok) {
            // A definitive 4xx means the bridge rejected the association.
            if (response.status >= 400 && response.status < 500)
                await clearBridgeJobForTab(tabId);

            throw new Error(body?.error || `bridge returned ${response.status}`);
        }

        return body;
    } catch (e) {
        // On a transient network failure keep the mapping. The attach page can
        // retry idempotently, and the recorder will not continue until the
        // bridge confirms the association.
        throw e;
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
        job_id: typeof record?.python_bridge_job_id === "string"
            ? record.python_bridge_job_id
            : null,
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

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message?.type === "PYTHON_BRIDGE_ATTACH") {
        const jobId = message?.payload?.job_id;
        const tabId = sender?.tab?.id;

        if (!PYTHON_BRIDGE_JOB_ID_RE.test(jobId || "") || !Number.isInteger(tabId) || tabId < 0) {
            sendResponse({ ok: false, error: "invalid bridge job or tab" });
            return;
        }

        attachBridgeJobToTab(jobId, tabId)
            .then(() => sendResponse({ ok: true, job_id: jobId, tab_id: tabId }))
            .catch((error) => sendResponse({ ok: false, error: error?.message || String(error) }));

        return true;
    }

    if (message?.type === "PYTHON_BRIDGE_GET_JOB") {
        const tabId = sender?.tab?.id;
        if (!Number.isInteger(tabId) || tabId < 0) {
            sendResponse({ ok: false, error: "invalid tab" });
            return;
        }

        getBridgeJobForTab(tabId)
            .then((jobId) => sendResponse({ ok: true, job_id: jobId }))
            .catch((error) => sendResponse({ ok: false, error: error?.message || String(error) }));

        return true;
    }
});

chrome.tabs.onRemoved.addListener((tabId) => {
    clearBridgeJobForTab(tabId).catch(() => {});
});

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
