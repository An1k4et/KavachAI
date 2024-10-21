document.addEventListener('DOMContentLoaded', function() {
    chrome.storage.local.get("phishingStatus", function(result) {
      const status = result.phishingStatus;
      const statusDiv = document.getElementById('status');
  
      if (status === 1) {
        statusDiv.innerText = "This website is legitimate.";
        statusDiv.classList.add("legitimate");
      } else if (status === 0) {
        statusDiv.innerText = "This website is suspicious.";
        statusDiv.classList.add("suspicious");
      } else if (status === -1) {
        statusDiv.innerText = "This website is fake!";
        statusDiv.classList.add("fake");
      } else {
        statusDiv.innerText = "No data available.";
      }
    });
  });
  