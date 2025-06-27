// static/js/charts.js
document.addEventListener('DOMContentLoaded', () => {
    // Risk Level Chart
    const ctxLevel = document.getElementById('levelChart');
    if (ctxLevel) {
        new Chart(ctxLevel, {
            type: 'pie',
            data: {
                labels: Object.keys(levelData),
                datasets: [{
                    label: 'Risk Levels',
                    data: Object.values(levelData),
                    backgroundColor: ['#e74c3c', '#f1c40f', '#2ecc71'] // red, yellow, green
                }]
            }
        });
    }

    // Risk Status Chart
    const ctxStatus = document.getElementById('statusChart');
    if (ctxStatus) {
        new Chart(ctxStatus, {
            type: 'doughnut',
            data: {
                labels: Object.keys(statusData),
                datasets: [{
                    label: 'Risk Statuses',
                    data: Object.values(statusData),
                    backgroundColor: ['#3498db', '#95a5a6', '#8e44ad'] // blue, grey, purple
                }]
            }
        });
    }

    // Control Type Chart
    const ctxControl = document.getElementById('controlChart');
    if (ctxControl) {
        new Chart(ctxControl, {
            type: 'bar',
            data: {
                labels: Object.keys(controlData),
                datasets: [{
                    label: 'Controls Distribution',
                    data: Object.values(controlData),
                    backgroundColor: '#1abc9c' // teal
                }]
            },
            options: {
                scales: {
                    y: { beginAtZero: true }
                }
            }
        });
    }
});