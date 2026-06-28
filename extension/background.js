// Shadow AI Detector - background service worker
// Keeps a running count badge on the toolbar icon.

let count = 0;

chrome.runtime.onMessage.addListener((msg) => {
  if (msg && msg.kind === "bump") {
    count += 1;
    chrome.action.setBadgeText({ text: String(count) });
    chrome.action.setBadgeBackgroundColor({ color: "#DC2626" });
  }
});
