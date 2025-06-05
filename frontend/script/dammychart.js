
    document.addEventListener('DOMContentLoaded', () => {
    const dummyData = {
        '7': [2, 4, 1, 3, 5, 2, 0],
        '30': [10, 15, 8, 12, 20, 16, 18, 14, 22, 25, 19, 17, 23, 21, 20, 19, 22, 25, 24, 26, 28, 30, 27, 29, 31, 32, 35, 33, 34, 36],
        '90': Array(90).fill().map(() => Math.floor(Math.random() * 50)),
        '365': Array(365).fill().map(() => Math.floor(Math.random() * 100))
    };

    const ctx = document.getElementById('vulnChart').getContext('2d');

    let chart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: Array.from({length: 90}, (_, i) => i + 1),  // default to 90 days
            datasets: [{
                label: 'Vulnerabilities',
                data: dummyData['90'],
                borderColor: 'rgba(75, 192, 192, 1)',
                backgroundColor: 'rgba(75, 192, 192, 0.2)',
                fill: true,
                tension: 0.1
            }]
        },
        options: {
            responsive: true,
            scales: {
                x: { display: true, title: { display: true, text: 'Days' } },
                y: { display: true, title: { display: true, text: 'Count' }, beginAtZero: true }
            }
        }
    });

    document.getElementById('timeRange').addEventListener('change', (e) => {
        const range = e.target.value;
        chart.data.labels = Array.from({length: parseInt(range)}, (_, i) => i + 1);
        chart.data.datasets[0].data = dummyData[range];
        chart.update();
    });
});

