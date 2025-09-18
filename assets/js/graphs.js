// graphs.js : logique spécifique à la génération de graphiques

var image;

window.chartColors = {
    red: 'rgb(255, 99, 132)',
    orange: 'rgb(255, 159, 64)',
    yellow: 'rgb(255, 205, 86)',
    green: 'rgb(162, 213, 114)',
    blue: 'rgb(54, 162, 235)'
};

var color = Chart.helpers.color;

// Configuration du graphique en barres
var config_bar = {
    type: 'bar',
    data: {
        labels: ["Low", "Medium", "High", "Critical"],
        datasets: [{
            label: "Number of vulnerabilities",
            backgroundColor: [
                window.chartColors.green, 
                window.chartColors.yellow, 
                window.chartColors.orange, 
                window.chartColors.red
            ],
            data: [0, 0, 0, 0],
        }]
    },
    plugins: [ChartDataLabels],
    options: {
        responsive: true,
        maintainAspectRatio: false,
        title: {
            display: true,
            text: 'Number of vulnerabilities per severity'
        },
        plugins: {
            legend: {
                display: false
            },
            tooltip: {
                enabled: false
            },
            datalabels: {
                font: {
                    weight: 'bold',
                    size: 14
                },
                color: 'white'
            }
        },
        scales: {
            y: {
                beginAtZero: true,
                grid: {
                    color: 'rgba(255, 255, 255, 0.1)'
                },
                ticks: {
                    color: 'white'
                }
            },
            x: {
                grid: {
                    color: 'rgba(255, 255, 255, 0.1)'
                },
                ticks: {
                    color: 'white'
                }
            }
        }
    }
};

// Configuration du graphique en secteurs
var config_pie = {
    type: 'pie',
    data: {
        datasets: [{
            data: [0, 0, 0, 0],
            backgroundColor: [
                window.chartColors.green, 
                window.chartColors.yellow, 
                window.chartColors.orange, 
                window.chartColors.red
            ],
            label: 'Dataset 1',
        }],
        labels: ["Low", "Medium", "High", "Critical"]
    },
    plugins: [ChartDataLabels],
    options: {
        responsive: true,
        maintainAspectRatio: false,
        title: {
            display: true,
            text: 'Number of vulnerabilities per severity'
        },
        plugins: {
            legend: {
                display: true,
                position: 'bottom',
                labels: {
                    color: 'white'
                }
            },
            tooltip: {
                enabled: false
            },
            datalabels: {
                font: {
                    weight: 'bold',
                    size: 14
                },
                color: 'white'
            }
        }
    }
};

var myBar;
var myPie;

// Initialisation des graphiques
window.onload = function () {
    myBar = new Chart(document.getElementById("canvas_bar"), config_bar);
    myPie = new Chart(document.getElementById("canvas_pie"), config_pie);
    action_bar();
    action_pie();
    
    // Ajouter des animations d'entrée
    setTimeout(() => {
        document.querySelectorAll('.glass-card').forEach((card, index) => {
            card.style.animationDelay = `${index * 0.1}s`;
        });
    }, 100);
};

// Télécharger le graphique en barres
function download_bar() {
    var a = document.createElement("a");
    a.href = myBar.toBase64Image();
    a.download = "vulnerabilities_bar_chart.png";
    a.click();
    
    // Notification de succès
    showNotification('success', 'Bar Chart Downloaded', 'Chart saved successfully as PNG');
}

// Télécharger le graphique en secteurs
function download_pie() {
    var a = document.createElement("a");
    a.href = myPie.toBase64Image();
    a.download = "vulnerabilities_pie_chart.png";
    a.click();
    
    // Notification de succès
    showNotification('success', 'Pie Chart Downloaded', 'Chart saved successfully as PNG');
}

// Sélectionner du texte
function SelectText(element) {
    var doc = document;
    if (doc.body.createTextRange) {
        var range = document.body.createTextRange();
        range.moveToElementText(element);
        range.select();
    } else if (window.getSelection) {
        var selection = window.getSelection();
        var range = document.createRange();
        range.selectNodeContents(element);
        selection.removeAllRanges();
        selection.addRange(range);
    }
}

// Mettre à jour le graphique en barres
function action_bar() {
    config_bar.data.datasets[0].data[0] = parseInt(document.getElementById("low").value) || 0;
    config_bar.data.datasets[0].data[1] = parseInt(document.getElementById("medium").value) || 0;
    config_bar.data.datasets[0].data[2] = parseInt(document.getElementById("high").value) || 0;
    config_bar.data.datasets[0].data[3] = parseInt(document.getElementById("critical").value) || 0;
    myBar.update();
}

// Copier le graphique en barres
function copy_bar() {
    var canvas = document.getElementById("canvas_bar");
    var img = document.createElement('img');
    img.src = canvas.toDataURL();
    var div = document.createElement('div');
    div.contentEditable = true;
    div.appendChild(img);
    document.body.appendChild(div);
    
    // Copier
    SelectText(div);
    document.execCommand('Copy');
    document.body.removeChild(div);
    
    // Notification de succès
    showNotification('success', 'Bar Chart Copied', 'Chart copied to clipboard successfully');
}

// Mettre à jour le graphique en secteurs
function action_pie() {
    config_pie.data.datasets[0].data[0] = parseInt(document.getElementById("low").value) || 0;
    config_pie.data.datasets[0].data[1] = parseInt(document.getElementById("medium").value) || 0;
    config_pie.data.datasets[0].data[2] = parseInt(document.getElementById("high").value) || 0;
    config_pie.data.datasets[0].data[3] = parseInt(document.getElementById("critical").value) || 0;
    myPie.update();
}

// Copier le graphique en secteurs
function copy_pie() {
    var canvas = document.getElementById("canvas_pie");
    var img = document.createElement('img');
    img.src = canvas.toDataURL();
    var div = document.createElement('div');
    div.contentEditable = true;
    div.appendChild(img);
    document.body.appendChild(div);
    
    // Copier
    SelectText(div);
    document.execCommand('Copy');
    document.body.removeChild(div);
    
    // Notification de succès
    showNotification('success', 'Pie Chart Copied', 'Chart copied to clipboard successfully');
}

// Fonction utilitaire pour les notifications
function showNotification(status, title, text) {
    new Notify({
        status: status,
        title: title,
        text: text,
        effect: 'fade',
        speed: 300,
        customClass: '',
        customIcon: '',
        showIcon: true,
        showCloseButton: true,
        autoclose: true,
        autotimeout: 2000,
        gap: 20,
        distance: 20,
        type: 1,
        position: 'top right'
    });
}

// Validation des entrées
document.addEventListener('DOMContentLoaded', function() {
    const inputs = document.querySelectorAll('input[type="number"]');
    inputs.forEach(input => {
        input.addEventListener('input', function() {
            if (this.value < 0) this.value = 0;
            if (this.value > 999) this.value = 999;
        });
    });
});
