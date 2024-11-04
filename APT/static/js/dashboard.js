const ctx = document.getElementById('modelPerformanceChart').getContext('2d');

const modelPerformanceChart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: [100, 500, 1000, 2000], // Training Iterations
        datasets: [
            {
                label: 'Model A',
                data: [70, 80, 90, 95], // Performance data for Model A
                borderColor: '#3498db',
                backgroundColor: 'rgba(52, 152, 219, 0.1)',
                borderWidth: 2,
                fill: true,
                pointRadius: 5,
                pointHoverRadius: 7,
            },
            {
                label: 'Model B',
                data: [60, 75, 85, 92], // Performance data for Model B
                borderColor: '#f1c40f',
                backgroundColor: 'rgba(241, 196, 15, 0.1)',
                borderWidth: 2,
                fill: true,
                pointRadius: 5,
                pointHoverRadius: 7,
            }
        ]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            x: {
                title: {
                    display: true,
                    text: 'Training Iterations'
                },
                ticks: {
                    color: '#333'
                }
            },
            y: {
                title: {
                    display: true,
                    text: 'Performance Metric (%)'
                },
                ticks: {
                    color: '#333'
                }
            }
        },
        plugins: {
            tooltip: {
                enabled: true,
                mode: 'index',
                intersect: false,
                callbacks: {
                    label: function (context) {
                        return `${context.dataset.label}: ${context.raw}%`;
                    }
                }
            },
            legend: {
                labels: {
                    color: '#333',
                    font: {
                        family: 'Montserrat'
                    }
                }
            }
        }
    }
});

document.querySelector('.fa-moon').addEventListener('click', () => {
    document.body.classList.toggle('dark-mode');
});

document.querySelector('.fa-expand').addEventListener('click', () => {
    if (!document.fullscreenElement) {
        document.documentElement.requestFullscreen();
    } else if (document.exitFullscreen) {
        document.exitFullscreen();
    }
});

document.querySelector('.search-button').addEventListener('click', () => {
    const query = document.querySelector('.search-bar input').value.toLowerCase();
    const cards = document.querySelectorAll('.card');
    let found = false;

    cards.forEach(card => {
        const cardContent = card.textContent.toLowerCase();
        if (cardContent.includes(query)) {
            card.style.display = 'block';
            found = true;
        } else {
            card.style.display = 'none';
        }
    });

    if (!found) {
        alert('No results found for: ' + query);
    }
});

