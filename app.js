async function runScan() {
  const outputDiv = document.getElementById("output");
  const progressSection = document.getElementById("progressSection");
  const progressBar = document.getElementById("progressBar");
  const currentDevice = document.getElementById("currentDevice");

  // Show the progress section
  progressSection.style.display = "block";
  progressBar.value = 0;
  currentDevice.innerText = "Starting scan...";

  outputDiv.innerHTML = "<p>Initializing scan ⏳</p>";

  try {
    // Start scan
    const response = await fetch("/run_scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        mode: document.getElementById("mode").value,
        discovery: document.getElementById("discovery").value,
        export: document.getElementById("export").value
      })
    });

    const data = await response.json();
    if (data.error) {
      outputDiv.innerHTML = `<p style="color:red">Error: ${data.error}</p>`;
      return;
    }

    // Listen for progress updates
    const evtSource = new EventSource("/progress");
    evtSource.onmessage = (e) => {
      const progressData = JSON.parse(e.data);
      const percent = (progressData.current / progressData.total) * 100;
      progressBar.value = percent;
      currentDevice.innerText = `Scanning: ${progressData.ip} (${progressData.current}/${progressData.total})`;

      if (progressData.current >= progressData.total) {
        evtSource.close();
        currentDevice.innerText = "Scan complete! Generating report...";
      }
    };

    // When the scan is done, poll for results every few seconds
    let checkResults = setInterval(async () => {
      try {
        const res = await fetch("/scan_results");
        if (res.ok) {
          const results = await res.json();
          if (Array.isArray(results) && results.length > 0) {
            clearInterval(checkResults);
            displayResults(results);
          }
        } else if (res.status === 404) {
          // Show loading message while waiting for results
          outputDiv.innerHTML = `<p>Scan in progress... waiting for results ⏳</p>`;
        } else {
          outputDiv.innerHTML = `<p style="color:red">Unexpected error fetching results.</p>`;
        }
      } catch (err) {
        outputDiv.innerHTML = `<p style="color:red">Error checking results: ${err.message}</p>`;
      }
    }, 5000);

  } catch (err) {
    outputDiv.innerHTML = `<p style="color:red">Error: ${err.message}</p>`;
  }
}

function displayResults(data) {
  const outputDiv = document.getElementById("output");
  const progressSection = document.getElementById("progressSection");
  
  // Hide progress section
  progressSection.style.display = "none";
  
  let html = `
    <table border="1" cellpadding="6">
      <tr>
        <th>IP</th><th>Hostname</th><th>Vendor</th><th>OS</th>
        <th>Role</th><th>Open Ports</th><th>Vulnerabilities</th>
      </tr>`;
  data.forEach(d => {
    html += `
      <tr>
        <td>${d.ip || ""}</td>
        <td>${d.hostname || ""}</td>
        <td>${d.vendor || ""}</td>
        <td>${d.os || ""}</td>
        <td>${d.role || ""}</td>
        <td>${d.open_ports || ""}</td>
        <td>${d.vulnerabilities || ""}</td>
      </tr>`;
  });
  html += "</table>";
  outputDiv.innerHTML = html;
}
