const token = sessionStorage.getItem('token');

if (!token) {
  window.location.href = 'login.html';
} else {
  // === Fetch User Info ===
  fetch('http://localhost:3000/api/user', {
    headers: { 'Authorization': `Bearer ${token}` }
  })
  .then(res => res.ok ? res.json() : Promise.reject('Failed to fetch user'))
  .then(user => {
    const userInfo = document.getElementById('user-info');
    if (userInfo) {
      const nameEl = userInfo.querySelector('h4');
      const roleEl = userInfo.querySelector('p');
      if (nameEl) nameEl.textContent = user.name || 'User';
      if (roleEl) roleEl.textContent = user.role || 'User';
    }

    const img = document.querySelector('.dash-user-panel img');
    if (img) {
      img.src = user.profile_picture || 'https://randomuser.me/api/portraits/men/32.jpg';
      img.alt = user.name || 'User Profile';
    }
  })
  .catch(err => console.error('User info error:', err));

  // === Helper: Percentage Change ===
  function calcPercentageChange(current, previous) {
    if (previous === 0) return current === 0 ? 0 : 100;
    return ((current - previous) / previous) * 100;
  }

  // === Fetch & Process Scan Data ===
  fetch('http://localhost:3000/api/scan/data', {
    headers: { 'Authorization': `Bearer ${token}` }
  })
  .then(res => res.ok ? res.json() : Promise.reject('Failed to fetch scans'))
  .then(scans => {
    const tbody = document.querySelector('.dash-scan-table tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    const now = new Date();
    const oneWeekAgo = new Date(now - 7 * 24 * 60 * 60 * 1000);
    const twoWeeksAgo = new Date(oneWeekAgo - 7 * 24 * 60 * 60 * 1000);

    let totalScans = 0, totalScansPrev = 0;
    let totalVulns = 0, totalVulnsPrev = 0;
    let protectedSites = new Set(), protectedSitesPrev = new Set();
    let totalUptime = 0, uptimeCount = 0, uptimePrevTotal = 0, uptimePrevCount = 0;

    scans.forEach(scan => {
      const scanDate = new Date(scan.scan_date || Date.now());
      const status = (scan.status || 'completed').toLowerCase();
      const website = scan.website || scan.url || 'N/A';
      const formattedDate = scanDate.toLocaleString();

      const statusClass = status === 'running' ? 'dash-status-running'
                        : status === 'failed' ? 'dash-status-failed'
                        : 'dash-status-completed';

      let actions = `<a href="#"><i class="fas fa-eye"></i></a>`;
      if (status === 'running') actions += `<a href="#"><i class="fas fa-stop"></i></a>`;
      else if (status === 'failed') actions += `<a href="#"><i class="fas fa-redo"></i></a>`;
      else actions += `<a href="#"><i class="fas fa-download"></i></a>`;

      tbody.innerHTML += `
        <tr>
          <td><div class="dash-scan-url"><i class="fas fa-globe"></i> ${website}</div></td>
          <td>${scan.type || 'Full'}</td>
          <td><span class="dash-status-badge ${statusClass}">${scan.status}</span></td>
          <td>${formattedDate}</td>
          <td class="dash-scan-actions">${actions}</td>
        </tr>
      `;

      let vulnCount = 0;
      if (typeof scan.vulnerabilities === 'object') {
        for (const sev in scan.vulnerabilities) {
          vulnCount += parseInt(scan.vulnerabilities[sev]) || 0;
        }
      } else if (typeof scan.vulnerabilities === 'number') {
        vulnCount = scan.vulnerabilities;
      }

      if (scanDate >= oneWeekAgo) {
        totalScans++;
        totalVulns += vulnCount;
        protectedSites.add(website);
        if (scan.uptime) {
          totalUptime += parseFloat(scan.uptime);
          uptimeCount++;
        }
      } else if (scanDate >= twoWeeksAgo) {
        totalScansPrev++;
        totalVulnsPrev += vulnCount;
        protectedSitesPrev.add(website);
        if (scan.uptime) {
          uptimePrevTotal += parseFloat(scan.uptime);
          uptimePrevCount++;
        }
      }
    });

    const avgUptime = uptimeCount ? totalUptime / uptimeCount : 0;
    const avgUptimePrev = uptimePrevCount ? uptimePrevTotal / uptimePrevCount : 0;

    const metrics = [
      {
        value: totalScans,
        change: calcPercentageChange(totalScans, totalScansPrev),
        compare: totalScans >= totalScansPrev
      },
      {
        value: totalVulns,
        change: calcPercentageChange(totalVulns, totalVulnsPrev),
        compare: totalVulns <= totalVulnsPrev
      },
      {
        value: protectedSites.size,
        change: calcPercentageChange(protectedSites.size, protectedSitesPrev.size),
        compare: protectedSites.size >= protectedSitesPrev.size
      },
      {
        value: avgUptime.toFixed(2) + '%',
        change: calcPercentageChange(avgUptime, avgUptimePrev),
        compare: avgUptime >= avgUptimePrev
      }
    ];

    const cards = document.querySelectorAll('.dash-metric-card');
    metrics.forEach((metric, i) => {
      const card = cards[i];
      if (!card) return;
      card.querySelector('.dash-card-value').textContent = metric.value;
      const changeEl = card.querySelector('.dash-card-change');
      changeEl.innerHTML = `
        <i class="fas fa-arrow-${metric.compare ? 'up' : 'down'}"></i>
        ${metric.change.toFixed(1)}% from last week
      `;
      changeEl.classList.toggle('positive', metric.compare);
      changeEl.classList.toggle('negative', !metric.compare);
    });
  })
  .catch(err => console.error('Error fetching scans data:', err));

  // === Fetch Current Scan Progress ===
  fetch('http://localhost:3000/api/scan/current', {
    headers: { 'Authorization': `Bearer ${token}` }
  })
  .then(res => res.ok ? res.json() : Promise.reject('Failed to fetch current scan'))
  .then(currentScan => {
    const progressBar = document.querySelector('.progress-bar');
    const progressPercent = document.querySelector('.progress-percent');
    const scanStats = document.querySelector('.scan-stats');

    if (progressBar && progressPercent && scanStats) {
      const percent = currentScan.percent || 0;
      progressBar.style.width = percent + '%';
      progressPercent.textContent = percent + '%';

      scanStats.innerHTML = `
        <div>Pages Scanned: ${currentScan.pages_scanned || 0}</div>
        <div>Critical Issues: ${currentScan.critical_issues || 0}</div>
        <div>Tests Completed: ${currentScan.tests_completed || 0}</div>
        <div>Elapsed Time: ${currentScan.elapsed_time || '0:00'}</div>
      `;
    }
  })
  .catch(err => console.error('Error fetching current scan:', err));
}


// common.js

//mobile menu toggle
document.addEventListener('DOMContentLoaded', function () {
  const hamburger = document.getElementById('toggle');
  const navLinks = document.querySelector('.nav-links');

  if (hamburger && navLinks) {
    hamburger.addEventListener('click', function () {
      this.classList.toggle('on');
      navLinks.classList.toggle('show');
    });
  }

  const statItems = document.querySelectorAll('.stat-item');
  const testimonialCards = document.querySelectorAll('.testimonial-card');

  function isInViewport(element) {
    const rect = element.getBoundingClientRect();
    return rect.top < window.innerHeight && rect.bottom >= 0;
  }

  function checkScroll() {
    statItems.forEach(item => isInViewport(item) && item.classList.add('active'));
    testimonialCards.forEach(card => isInViewport(card) && card.classList.add('active'));
  }

  window.addEventListener('scroll', checkScroll);
  window.addEventListener('load', checkScroll);
});



//logout js
const loginLogoutLink = document.getElementById('login-logout-link');

if (token) {
  // User is logged in → show Logout
  loginLogoutLink.textContent = 'Logout';
  loginLogoutLink.href = '#';
  loginLogoutLink.addEventListener('click', function (e) {
    e.preventDefault();
    sessionStorage.removeItem('token'); // Clear token on logout
    window.location.href = 'index.html'; // Redirect to login page
  });
} else {
  // User is not logged in → show Login
  loginLogoutLink.textContent = 'Login';
  loginLogoutLink.href = 'login.html';
}