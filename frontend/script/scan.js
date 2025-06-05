document.addEventListener('DOMContentLoaded', function () {
  const commonPorts = document.getElementById('commonPorts');
  const portStart = document.getElementById('portStart');
  const portEnd = document.getElementById('portEnd');
  const scanForm = document.getElementById('scanForm');
  const scanBtn = document.querySelector('.scanmain-btn');
  const saveBtn = document.querySelector('.scan-btn');

  const token = sessionStorage.getItem('token');

  if (!token) {
    window.location.href = 'login.html';
    return;
  }

  fetch('http://localhost:3000/api/dashboard', {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${token}` }
  }).then(res => {
    if (!res.ok) throw new Error('Unauthorized or session expired');
    return res.json();
  }).catch(() => {
    alert('Session expired or unauthorized. Please login again.');
    sessionStorage.removeItem('token');
    window.location.href = 'login.html';
  });

  if (commonPorts && portStart && portEnd) {
    commonPorts.addEventListener('change', function () {
      if (this.checked) {
        portStart.value = "1";
        portEnd.value = "1024";
      } else {
        portStart.value = "";
        portEnd.value = "";
      }
    });
  }

  if (scanForm) {
    scanForm.addEventListener('submit', async function (e) {
      e.preventDefault();

      const target = document.getElementById('target').value.trim();
      const scanName = document.getElementById('scan-name').value.trim() || 'Unnamed Scan';

      if (!target) {
        alert('Please enter a target URL or IP address');
        return;
      }

      const vulnChecks = Array.from(document.querySelectorAll('input[name="vulnChecks"]:checked'))
        .map(cb => cb.id.replace('Check', ''));

      const portScanEnabled = commonPorts.checked ||
        (portStart.value && portEnd.value && Number(portStart.value) > 0 && Number(portEnd.value) > 0);

      if (!vulnChecks.length && !portScanEnabled) {
        alert('Please select at least one scan feature');
        return;
      }

      const scanConfig = {
        target,
        selectedChecks: vulnChecks,
        portScan: {
          enabled: portScanEnabled,
          start: portScanEnabled ? portStart.value : null,
          end: portScanEnabled ? portEnd.value : null,
          commonOnly: commonPorts.checked
        }
      };

      scanBtn.disabled = true;
      scanBtn.classList.add('loading');
      scanBtn.innerHTML = `<i class="fas fa-spinner fa-spin"></i> Scanning...`;

      try {
        const res = await fetch('http://localhost:3000/api/scan', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
          },
          body: JSON.stringify(scanConfig)
        });

        if (!res.ok) throw new Error(`Scan request failed with status ${res.status}`);

        const result = await res.json();

        if (result.message && result.message.toLowerCase().includes('completed')) {
          alert(`✅ Scan "${scanName}" completed!`);

          const { jsPDF } = window.jspdf;
          const doc = new jsPDF();
          let y = 10;
          const lineHeight = 10;
          const pageHeight = doc.internal.pageSize.height;

          doc.setFontSize(16);
          doc.text(`Scan Report: ${scanName}`, 10, y);
          y += lineHeight;
          doc.setFontSize(12);
          doc.text(`Target: ${target}`, 10, y);
          y += lineHeight;

          function addTextBlock(title, text) {
            doc.setFontSize(14);
            doc.text(title, 10, y);
            y += lineHeight;

            doc.setFontSize(12);
            const splitText = doc.splitTextToSize(text, 190);
            splitText.forEach(line => {
              if (y > pageHeight - 20) {
                doc.addPage();
                y = 10;
              }
              doc.text(line, 10, y);
              y += 7;
            });
            y += lineHeight / 2;
          }

          // Add reports if exist
          if (vulnChecks.includes('csrf') && result.results.csrf) addTextBlock("CSRF Report", result.results.csrf.output);
          if (vulnChecks.includes('headers') && result.results.headers) addTextBlock("Headers Report", result.results.headers.output);
          if (portScanEnabled && result.results.port) addTextBlock("Port Scan Report", result.results.port.output);
          if (vulnChecks.includes('sqli') && result.results.sqli) addTextBlock("SQLi Report", result.results.sqli.output);
          if (vulnChecks.includes('xss') && result.results.xss) addTextBlock("XSS Report", result.results.xss.output);

if (result.message && result.message.toLowerCase().includes('completed')) {
  console.log('Full Scan Result:', result);
  console.log('Selected vulnChecks:', vulnChecks);

  if (vulnChecks.includes('csrf')) {
    console.log('CSRF result:', result.results.csrf);
  }

  // Baaki aapka existing code...
}


          // Generate base64 string for PDF
          const pdfBase64 = doc.output('datauristring'); // Data URI string
          const base64String = pdfBase64.split(',')[1]; // extract base64 part

          // Optionally save PDF locally
          // doc.save(`Scan_Report_${scanName.replace(/\s+/g, '_')}_${Date.now()}.pdf`);

          // Decode token for userId
          const decodedToken = JSON.parse(atob(token.split('.')[1]));
          const userId = decodedToken?.userId;

          // Extract severity counts from port output
          let critical = 0, high = 0, medium = 0, low = 0;
          let duration = null;

          const portOutput = result.results.port?.output;
          if (portOutput) {
            const match = portOutput.match(/Critical:\s*(\d+),\s*High:\s*(\d+),\s*Medium:\s*(\d+),\s*Low:\s*(\d+)/i);
            if (match) {
              critical = parseInt(match[1]);
              high = parseInt(match[2]);
              medium = parseInt(match[3]);
              low = parseInt(match[4]);
            }

            const durMatch = portOutput.match(/Scan duration:\s*([\d.]+)\s*seconds/i);
            if (durMatch) {
              duration = parseFloat(durMatch[1]);
            }
          }

          // Prepare scan data to save to backend
          const scanDataToSave = {
            scanName,
            url: target,
            status: 'completed',
            critical,
            high,
            medium,
            low,
            duration,
            user_id: userId,
            pdf_report: base64String // PDF base64 string here
          };

          console.log('Saving scan data with PDF to backend...');
          console.log('PDF base64 length:', base64String.length);

          // Save scan data with PDF to backend
          try {
            const saveRes = await fetch('http://localhost:3000/api/scan/scansave', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
              },
              body: JSON.stringify(scanDataToSave)
            });

            const saveResult = await saveRes.json();
            console.log('Scan data with PDF saved:', saveResult);

          } catch (saveErr) {
            console.error('Error saving scan data:', saveErr);
            alert('Scan completed but failed to save data to database.');
          }

        } else {
          alert('Scan completed but no confirmation message received.');
          console.log('Scan API response:', result);
        }

      } catch (err) {
        console.error('Scan error:', err);
        alert(`Failed to start scan: ${err.message}`);
      } finally {
        scanBtn.disabled = false;
        scanBtn.classList.remove('loading');
        scanBtn.innerHTML = 'Start Scan';
      }
    });
  }

  if (saveBtn) {
    saveBtn.addEventListener('click', function () {
      saveBtn.classList.add('clicked');
      saveBtn.disabled = true;

      alert("Feature coming soon: Save scan configuration as draft!");

      setTimeout(() => {
        saveBtn.classList.remove('clicked');
        saveBtn.disabled = false;
      }, 400);
    });
  }
});
