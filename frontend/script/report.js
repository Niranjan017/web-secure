
document.addEventListener('DOMContentLoaded', function () {
  const commonPorts = document.getElementById('commonPorts');
  const portStart = document.getElementById('portStart');
  const portEnd = document.getElementById('portEnd');
  const scanForm = document.getElementById('scanForm');
  const scanBtn = document.querySelector('.scanmain-btn');
  const reportsContainer = document.querySelector('.reports-grid');

  const token = sessionStorage.getItem('token');

  function parseJwt(token) {
    try {
      const base64Url = token.split('.')[1];
      const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
      const jsonPayload = decodeURIComponent(
        atob(base64)
          .split('')
          .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
          .join('')
      );
      return JSON.parse(jsonPayload);
    } catch (e) {
      return null;
    }
  }

  if (!token) {
    alert('No token found. Please log in.');
    window.location.href = 'login.html';
    return;
  }

  const decodedToken = parseJwt(token);
  if (!decodedToken || (decodedToken.exp && decodedToken.exp * 1000 < Date.now())) {
    alert('Session expired or invalid token. Please log in again.');
    sessionStorage.removeItem('token');
    window.location.href = 'login.html';
    return;
  }

  function checkResponse(res) {
    if (res.status === 401) {
      alert('Session expired or unauthorized. Please log in again.');
      sessionStorage.removeItem('token');
      window.location.href = 'login.html';
      throw new Error('Unauthorized');
    }
    if (!res.ok) {
      throw new Error(`Request failed with status ${res.status}`);
    }
    return res.json();
  }

  function createReportCard(scan) {
    const {
      id,
      title,
      url,
      status = 'Pending',
      critical = 0,
      high = 0,
      medium = 0,
      low = 0,
      duration
    } = scan;

    let durationStr = '--';
    if (typeof duration === 'number' || typeof duration === 'string') {
      durationStr = `${duration}s`;
    } else if (typeof duration === 'object' && duration !== null) {
      if ('seconds' in duration) {
        durationStr = `${duration.seconds}s`;
      } else if ('milliseconds' in duration) {
        durationStr = `${Math.round(duration.milliseconds / 1000)}s`;
      }
    }

    const statusClass = {
      completed: 'status-completed',
      running: 'status-running',
      failed: 'status-failed',
      pending: 'status-pending'
    }[status.toLowerCase()] || 'status-pending';

    const totalVulns = critical + high + medium + low;

    const today = new Date();
    const dateStr = `${today.getDate().toString().padStart(2, '0')}/${
      (today.getMonth() + 1).toString().padStart(2, '0')
    }/${today.getFullYear()}`;

    const card = document.createElement('div');
    card.className = 'report-card';
    card.dataset.id = id;

    card.innerHTML = `
      <div class="report-header">
        <div class="report-title">${title || url}</div>
        <div class="report-status ${statusClass}">${status.charAt(0).toUpperCase() + status.slice(1)}</div>
      </div>
      <div class="report-meta">
        <div><i class="fas fa-calendar-alt"></i> ${dateStr}</div>
        <div><i class="fas fa-clock"></i> ${durationStr}</div>
        <div><i class="fas fa-bug"></i> ${totalVulns > 0 ? totalVulns + ' Vulnerabilities' : 'No Vulnerabilities'}</div>
      </div>
      <div class="report-summary">
        <div class="summary-item"><span class="summary-label">Critical:</span> <span class="summary-value critical">${critical}</span></div>
        <div class="summary-item"><span class="summary-label">High:</span> <span class="summary-value high">${high}</span></div>
        <div class="summary-item"><span class="summary-label">Medium:</span> <span class="summary-value medium">${medium}</span></div>
        <div class="summary-item"><span class="summary-label">Low:</span> <span class="summary-value low">${low}</span></div>
      </div>
      <div class="report-actions">
        <a href="#" class="report-btn report-btn-outline download-pdf-btn" data-id="${id}" title="Download PDF">
          <i class="fas fa-download"></i> PDF
        </a>
        <a href="#" class="report-btn report-btn-outline report-btn-icon delete-report-btn" data-id="${id}" title="Delete Report">
          <i class="fas fa-trash-alt"></i>
        </a>
      </div>
    `;
    return card;
  }

  function renderReports(scans) {
    if (!reportsContainer) return;

    reportsContainer.innerHTML = '';

    if (!scans.length) {
      reportsContainer.innerHTML = '<p>No scan reports available.</p>';
      return;
    }

    scans.forEach(scan => {
      const card = createReportCard(scan);
      reportsContainer.appendChild(card);
    });
  }

  async function downloadPdf(scanId) {
    try {
      const res = await fetch(`http://localhost:3000/api/scan/report/${scanId}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (res.status === 401) {
        alert('Session expired or unauthorized. Please log in again.');
        sessionStorage.removeItem('token');
        window.location.href = 'login.html';
        return;
      }

      if (!res.ok) {
        throw new Error('Failed to download PDF report');
      }

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `scan_report_${scanId}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      alert(err.message);
      console.error('Download PDF error:', err);
    }
  }

  // 📌 Fixed and Simplified Event Delegation
  reportsContainer.addEventListener('click', function (e) {
    const downloadBtn = e.target.closest('.download-pdf-btn');
    if (downloadBtn) {
      e.preventDefault();
      const scanId = downloadBtn.dataset.id;
      if (scanId) downloadPdf(scanId);
    }

    const deleteBtn = e.target.closest('.delete-report-btn');
    if (deleteBtn) {
      e.preventDefault();
      alert('Delete logic goes here');
    }
  });

  // Auto-fill ports if "Common Ports" is checked
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

  // Handle Scan Form Submission
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
        scanName,
        selectedChecks: vulnChecks,
        portScan: {
          enabled: portScanEnabled,
          start: portScanEnabled ? portStart.value : null,
          end: portScanEnabled ? portEnd.value : null,
          commonOnly: commonPorts.checked
        },
        timestamp: new Date().toISOString()
      };

      scanBtn.disabled = true;
      scanBtn.classList.add('loading');
      scanBtn.innerHTML = `<i class="fas fa-spinner fa-spin"></i> Scanning...`;

      try {
        const res = await fetch('http://localhost:3000/api/scan', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
          },
          body: JSON.stringify(scanConfig)
        });

        if (res.status === 401) {
          alert('Session expired or unauthorized. Please log in again.');
          sessionStorage.removeItem('token');
          window.location.href = 'login.html';
          return;
        }

        if (!res.ok) {
          throw new Error('Failed to start scan');
        }

        const result = await res.json();
        alert('Scan started successfully!');

        // Refresh reports
        fetch('http://localhost:3000/api/scan/data', {
          method: 'GET',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
          }
        })
          .then(checkResponse)
          .then(renderReports);

      } catch (err) {
        alert(err.message);
        console.error('Scan error:', err);
      } finally {
        scanBtn.disabled = false;
        scanBtn.classList.remove('loading');
        scanBtn.innerHTML = 'Start Scan';
      }
    });
  }

  // Initial fetch
  fetch('http://localhost:3000/api/scan/data', {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
  })
    .then(checkResponse)
    .then(renderReports)
    .catch(err => {
      console.error('Report fetch error:', err);
    });

});

