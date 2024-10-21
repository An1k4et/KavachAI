// Function to check the legitimacy of a URL
function checkUrlLegitimacy(url) {
    if (url.startsWith("http://") || url.startsWith("https://")) {
        fetch('http://127.0.0.1:5000/process_url', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url })
        })
        .then(response => response.json())
        .then(data => {
            if (data && data.phishing_status !== undefined) {
                chrome.storage.local.set({ "phishingStatus": data.phishing_status });
            } else {
                console.log('No phishing status in the response');
            }
        })
        .catch(err => console.error('Error fetching URL check:', err));
    } else {
        console.log("Invalid URL schema (not http/https):", url);
    }
}

// Listener for tab updates (when a new URL is loaded)
chrome.tabs.onUpdated.addListener(function (tabId, changeInfo, tab) {
    if (changeInfo.status === "complete" && tab.url) {
        checkUrlLegitimacy(tab.url);
    }
});

// Listener for tab activation (when switching tabs)
chrome.tabs.onActivated.addListener(function (activeInfo) {
    chrome.tabs.get(activeInfo.tabId, function(tab) {
        if (tab.url) {
            checkUrlLegitimacy(tab.url);
        }
    });
});
