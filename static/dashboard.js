document.addEventListener('DOMContentLoaded', function() {
    const token = localStorage.getItem('jwtToken');
    if (!token) {
        window.location.href = '/login';
        return;
    }

    const ctx = document.getElementById('trafficChart').getContext('2d');
    const chart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Requests per IP',
                data: [],
                backgroundColor: 'rgba(54, 162, 235, 0.5)',
                borderColor: 'rgba(54, 162, 235, 1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                }
            }
        }
    });

    fetch('/validate-token', {
        headers: {
            'Authorization': `Bearer ${token}`
        }
    })
    .then(response => {
        if (!response.ok) throw new Error('Invalid session');
        return response.json();
    })
    .then(data => {
        if (data.valid && data.role === 'admin') {
            startDashboardUpdates();
        } else {
            window.location.href = '/user-home';
        }
    })
    .catch(error => {
        console.error('Validation error:', error);
        localStorage.removeItem('jwtToken');
        window.location.href = '/login';
    });

    function updateList(listId, items) {
        const list = document.getElementById(listId);
        list.innerHTML = items.map(ip => `<li class="ip-item">${ip}</li>`).join('');
    }

    function updateDashboard() {
        fetch('/dashboard-data', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        })
        .then(response => {
            if (!response.ok) {
                if (response.status === 401 || response.status === 403) {
                    localStorage.removeItem('jwtToken');
                    window.location.href = '/login';
                }
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            document.getElementById('totalIps').textContent = data.total_ips;
            document.getElementById('blockedIps').textContent = data.blocked_ips.length;
            document.getElementById('suspiciousIps').textContent = data.suspicious_ips.length;
            
            const ips = Object.keys(data.request_counts);
            const counts = ips.map(ip => data.request_counts[ip]);
            chart.data.labels = ips;
            chart.data.datasets[0].data = counts;
            chart.update();
            
            updateList('blockedList', data.blocked_ips);
            updateList('suspiciousList', data.suspicious_ips);
            
            const warningDiv = document.getElementById('bruteForceWarning');
            if (data.brute_force_ips.length > 0) {
                const messages = data.brute_force_ips.map(obj => `${obj.ip} (${obj.remaining} sec remaining)`);
                warningDiv.textContent = `Brute-force attack detected! IPs: ${messages.join(', ')}`;
            } else {
                warningDiv.textContent = '';
            }
        })
        .catch(error => {
            console.error('Dashboard update error:', error);
        });
    }

    function startDashboardUpdates() {
        updateDashboard();
        const updateInterval = setInterval(updateDashboard, 2000);
        window.addEventListener('beforeunload', () => clearInterval(updateInterval));
    }

    document.body.addEventListener('click', function(e) {
        if (e.target.id === 'logoutButton') {
            localStorage.removeItem('jwtToken');
            window.location.href = '/login';
        }
    });
});
