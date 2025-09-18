// calculatrice.js : logique spécifique à la calculatrice CVSS

let score_cvss = 0.0;
let myRadar;

window.chartColors = {
    red: 'rgb(255, 99, 132)',
    orange: 'rgb(255, 159, 64)',
    yellow: 'rgb(255, 205, 86)',
    green: 'rgb(162, 213, 114)',
    blue: 'rgb(54, 162, 235)'
};

const color = Chart.helpers.color;

const centerText = {
    beforeDraw: function (chart) {
        const width = chart.width;
        const height = chart.height;
        const ctx = chart.ctx;
        ctx.restore();
        const fontSize = (height / 114).toFixed(2);
        ctx.font = 'bold ' + fontSize + 'em sans-serif';
        ctx.textBaseline = 'middle';
        ctx.fillStyle = 'white';
        ctx.strokeStyle = 'black';
        const text = score_cvss;
        const textX = Math.round((width - (ctx.measureText(text).width)) / 2 - 16);
        const textY = height / 2;
        ctx.fillText(text, textX, textY);
        ctx.strokeText(text, textX, textY);
        ctx.save();
    }
};

const config_radar = {
    type: 'radar',
    data: {
        labels: [
            "Integrity", "Availability", "Access vector", "Attack complexity", "Privileges required", "User interaction", "Scope", "Confidentiality"
        ],
        datasets: [{
            label: "Score",
            backgroundColor: color(window.chartColors.red).alpha(0.2).rgbString(),
            borderColor: window.chartColors.red,
            pointBackgroundColor: window.chartColors.red,
            data: [1, 1, 1, 1, 1, 1, 1, 1],
        }]
    },
    options: {
        responsive: true,
        plugins: {
            legend: { display: false },
            tooltip: { enabled: false }
        },
        scales: {
            r: {
                min: -1,
                max: 2,
                ticks: { display: false, stepSize: 1 }
            }
        }
    },
    plugins: [centerText]
};

window.onload = function () {
    myRadar = new Chart(document.getElementById("canvas"), config_radar);
};

function download_radar() {
    const a = document.createElement("a");
    a.href = myRadar.toBase64Image();
    a.download = "Image.png";
    a.click();
}

async function download_metrics() {
    // Récupérer les valeurs actuelles
    const exploitabilityValue = document.getElementById("exploitability").textContent;
    const impactValue = document.getElementById("impact").textContent;
    const riskValue = document.getElementById("risk").textContent;
    
    // Créer un canvas personnalisé avec un design optimisé
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    
    // Dimensions optimales
    canvas.width = 600;
    canvas.height = 400;
    
    // Fond dégradé
    const gradient = ctx.createLinearGradient(0, 0, 0, canvas.height);
    gradient.addColorStop(0, '#1a2035');
    gradient.addColorStop(0.5, '#2c3e50');
    gradient.addColorStop(1, '#34495e');
    ctx.fillStyle = gradient;
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    
    // Bordure principale
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.2)';
    ctx.lineWidth = 2;
    ctx.strokeRect(10, 10, canvas.width - 20, canvas.height - 20);
    
    // Titre
    ctx.fillStyle = '#ffffff';
    ctx.font = 'bold 28px Lato, Arial, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('CVSS 3.1 Metrics', canvas.width / 2, 50);
    
    // Fonction pour dessiner une métrique
    function drawMetric(y, icon, label, value, color, isMain = false) {
        const boxHeight = isMain ? 80 : 60;
        const boxY = y;
        
        // Fond de la métrique avec dégradé
        const metricGradient = ctx.createLinearGradient(50, boxY, 550, boxY + boxHeight);
        metricGradient.addColorStop(0, 'rgba(255, 255, 255, 0.1)');
        metricGradient.addColorStop(1, 'rgba(255, 255, 255, 0.05)');
        
        ctx.fillStyle = metricGradient;
        ctx.fillRect(50, boxY, 500, boxHeight);
        
        // Bordure de la métrique
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.2)';
        ctx.lineWidth = 1;
        ctx.strokeRect(50, boxY, 500, boxHeight);
        
        // Icône (emoji ou symbol)
        ctx.font = '24px Arial';
        ctx.fillStyle = color;
        ctx.textAlign = 'left';
        ctx.fillText(icon, 70, boxY + (boxHeight / 2) + 8);
        
        // Label
        ctx.font = isMain ? 'bold 20px Lato, Arial, sans-serif' : 'bold 18px Lato, Arial, sans-serif';
        ctx.fillStyle = '#ffffff';
        ctx.fillText(label, 110, boxY + (boxHeight / 2) + 6);
        
        // Valeur dans une bulle
        const valueWidth = isMain ? 120 : 100;
        const valueX = 550 - valueWidth - 20;
        const valueY = boxY + (boxHeight - 35) / 2;
        
        // Fond de la valeur
        const valueGradient = ctx.createLinearGradient(valueX, valueY, valueX + valueWidth, valueY + 35);
        if (isMain) {
            valueGradient.addColorStop(0, '#6c7ae0');
            valueGradient.addColorStop(1, '#9b59b6');
        } else {
            valueGradient.addColorStop(0, color);
            valueGradient.addColorStop(1, color + '80');
        }
        
        ctx.fillStyle = valueGradient;
        ctx.fillRect(valueX, valueY, valueWidth, 35);
        
        // Bordure de la valeur
        ctx.strokeStyle = isMain ? 'rgba(255, 255, 255, 0.3)' : 'rgba(255, 255, 255, 0.2)';
        ctx.lineWidth = 2;
        ctx.strokeRect(valueX, valueY, valueWidth, 35);
        
        // Texte de la valeur
        ctx.font = isMain ? 'bold 18px Lato, Arial, sans-serif' : 'bold 16px Lato, Arial, sans-serif';
        ctx.fillStyle = '#ffffff';
        ctx.textAlign = 'center';
        ctx.fillText(value, valueX + valueWidth / 2, valueY + 23);
    }
    
    // Dessiner les métriques
    drawMetric(90, '🎯', 'Exploitability', exploitabilityValue, '#f39c12');
    drawMetric(170, '⚠️', 'Impact', impactValue, '#e74c3c');
    drawMetric(260, '🛡️', 'Risk Score', riskValue, '#3498db', true);
    
    // Timestamp en bas
    //ctx.font = '12px Arial';
    //ctx.fillStyle = 'rgba(255, 255, 255, 0.6)';
    //ctx.textAlign = 'center';
    //const date = new Date().toLocaleDateString();
    //ctx.fillText(`Generated on ${date} - Pentest Helper`, canvas.width / 2, canvas.height - 15);
    
    // Télécharger l'image
    const link = document.createElement('a');
    link.download = 'cvss-metrics.png';
    link.href = canvas.toDataURL('image/png');
    link.click();
}

function SelectText(element) {
    const doc = document;
    if (doc.body.createTextRange) {
        const range = document.body.createTextRange();
        range.moveToElementText(element);
        range.select();
    } else if (window.getSelection) {
        const selection = window.getSelection();
        const range = document.createRange();
        range.selectNodeContents(element);
        selection.removeAllRanges();
        selection.addRange(range);
    }
}

async function copy(id, isTable) {
    let canvas;
    if (isTable) {
        const a = document.createElement("a");
        await html2canvas(document.getElementById(id)).then((c) => {
            a.appendChild(c);
        });
        canvas = a.childNodes[0];
    } else {
        canvas = document.getElementById(id);
    }
    const img = document.createElement('img');
    img.src = canvas.toDataURL();
    const div = document.createElement('div');
    div.contentEditable = true;
    div.appendChild(img);
    document.body.appendChild(div);
    SelectText(div);
    document.execCommand('Copy');
    document.body.removeChild(div);
    new Notify({
        status: 'success',
        title: 'Elément copié avec succès',
        effect: 'fade',
        speed: 300,
        showIcon: true,
        showCloseButton: true,
        autoclose: true,
        autotimeout: 1500,
        gap: 20,
        distance: 20,
        type: 1,
        position: 'top right'
    });
}


// Arrondi spécifique pour le score CVSS
function roundUp1(input) {
    const intInput = Math.round(input * 100000);
    if (intInput % 10000 === 0) {
        return intInput / 100000;
    } else {
        return (Math.floor(intInput / 10000) + 1) / 10;
    }
}

// Initialisation du composant CVSS et gestion du hash dans l'URL
let c;
window.addEventListener('DOMContentLoaded', () => {
    c = new CVSS("cvssboard", {
        onchange: function () {
            window.location.hash = c.get().vector;
            c.vector.setAttribute('href', '#' + c.get().vector);
            action();
        }
    });
    if (window.location.hash.substring(1).length > 0) {
        c.set(decodeURIComponent(window.location.hash.substring(1)));
    }
});

// Fonction principale de calcul et d'affichage des métriques
function action() {
    const tmp = c.get().vector.split("/");
    const score = { AV: 0, AC: 0, PR: 0, UI: 0, S: 0, C: 0, I: 0, A: 0 };
    const radar_point = { AV: 0, AC: 0, PR: 0, UI: 0, S: 0, C: 0, I: 0, A: 0 };
    for (let index = 1; index < tmp.length; index++) {
        const [type, selection] = tmp[index].split(":");
        switch (type) {
            case "AV":
                switch (selection) {
                    case "N": score[type] = 0.85; radar_point[type] = 2; break;
                    case "A": score[type] = 0.62; radar_point[type] = 1; break;
                    case "L": score[type] = 0.55; radar_point[type] = 0; break;
                    case "P": score[type] = 0.2; radar_point[type] = 0; break;
                }
                break;
            case "AC":
                switch (selection) {
                    case "H": score[type] = 0.44; radar_point[type] = 0; break;
                    case "L": score[type] = 0.77; radar_point[type] = 2; break;
                }
                break;
            case "PR":
                switch (selection) {
                    case "N": score[type] = "N"; radar_point["PR"] = 2; break;
                    case "L": score[type] = "L"; radar_point["PR"] = 1; break;
                    case "H": score[type] = "H"; radar_point["PR"] = 0; break;
                }
                break;
            case "UI":
                switch (selection) {
                    case "N": score[type] = 0.85; radar_point[type] = 2; break;
                    case "R": score[type] = 0.62; radar_point[type] = 0; break;
                }
                break;
            case "S":
                switch (selection) {
                    case "U": score[type] = 6.42; radar_point[type] = 0; break;
                    case "C": score[type] = 7.52; radar_point[type] = 2; break;
                }
                break;
            case "C":
            case "I":
            case "A":
                switch (selection) {
                    case "N": score[type] = 0.0; radar_point[type] = 0; break;
                    case "L": score[type] = 0.22; radar_point[type] = 1; break;
                    case "H": score[type] = 0.56; radar_point[type] = 2; break;
                }
                break;
        }
    }

    // Calcul du score PR selon la portée
    if (score.S === 6.42) {
        switch (score.PR) {
            case "N": score.PR = 0.85; break;
            case "L": score.PR = 0.62; break;
            case "H": score.PR = 0.27; break;
        }
    } else {
        switch (score.PR) {
            case "N": score.PR = 0.85; break;
            case "L": score.PR = 0.68; break;
            case "H": score.PR = 0.5; break;
        }
    }

    score_cvss = c.get().score;

    // Calcul de l'impact
    let impact = 1 - (1 - score.C) * (1 - score.I) * (1 - score.A);
    if (score.S === 6.42) {
        impact = 6.42 * impact;
    } else {
        impact = 7.52 * (impact - 0.029) - 3.25 * Math.pow((impact - 0.02), 15);
    }
    impact = Math.round(impact * 10) / 10;
    const impact_metric = impact;

    // Affichage de l'impact
    let impactLabel = "";
    if (impact <= 2.5) {
        impactLabel = "Minor";
        document.getElementById("impact").style.color = window.chartColors.green;
    } else if (impact > 2.5 && impact <= 4) {
        impactLabel = "Important";
        document.getElementById("impact").style.color = window.chartColors.yellow;
    } else if (impact > 4 && impact <= 5.5) {
        impactLabel = "Major";
        document.getElementById("impact").style.color = window.chartColors.orange;
    } else {
        impactLabel = "Critical";
        document.getElementById("impact").style.color = window.chartColors.red;
    }
    document.getElementById("impact").innerHTML = impactLabel + " " + impact_metric;

    // Calcul de l'exploitabilité
    let exploitability = 8.22 * score.AV * score.AC * score.PR * score.UI;
    exploitability = Math.round(exploitability * 10) / 10;
    const exploitability_metric = exploitability;
    let virt_exploitability = exploitability;
    if (score.S === 6.42 && exploitability === 4) {
        exploitability -= 1;
    }

    // Affichage de l'exploitabilité
    let exploitabilityLabel = "";
    if (exploitability <= 1) {
        exploitabilityLabel = "Very hard";
        document.getElementById("exploitability").style.color = window.chartColors.green;
    } else if (exploitability > 1 && exploitability <= 2) {
        exploitabilityLabel = "Hard";
        document.getElementById("exploitability").style.color = window.chartColors.yellow;
    } else if (exploitability > 2 && exploitability <= 3) {
        exploitabilityLabel = "Medium";
        document.getElementById("exploitability").style.color = window.chartColors.orange;
    } else {
        exploitabilityLabel = "Easy";
        document.getElementById("exploitability").style.color = window.chartColors.red;
    }
    document.getElementById("exploitability").innerHTML = exploitabilityLabel + " " + exploitability_metric;

    // Calcul du risque
    const risk_matrix = {
        "Minor": { "Very hard": "Minor", "Hard": "Minor", "Medium": "Important", "Easy": "Important" },
        "Important": { "Very hard": "Minor", "Hard": "Important", "Medium": "Important", "Easy": "Major" },
        "Major": { "Very hard": "Important", "Hard": "Important", "Medium": "Major", "Easy": "Critical" },
        "Critical": { "Very hard": "Important", "Hard": "Major", "Medium": "Critical", "Easy": "Critical" }
    };
    const risk = risk_matrix[impactLabel][exploitabilityLabel];
    document.getElementById("risk").innerHTML = risk;
    switch (risk) {
        case "Minor": document.getElementById("risk").style.color = window.chartColors.green; break;
        case "Important": document.getElementById("risk").style.color = window.chartColors.yellow; break;
        case "Major": document.getElementById("risk").style.color = window.chartColors.orange; break;
        case "Critical": document.getElementById("risk").style.color = window.chartColors.red; break;
    }

    // Mise à jour du radar
    config_radar.data.datasets[0].data[0] = radar_point.I;
    config_radar.data.datasets[0].data[1] = radar_point.A;
    config_radar.data.datasets[0].data[2] = radar_point.AV;
    config_radar.data.datasets[0].data[3] = radar_point.AC;
    config_radar.data.datasets[0].data[4] = radar_point.PR;
    config_radar.data.datasets[0].data[5] = radar_point.UI;
    config_radar.data.datasets[0].data[6] = radar_point.S;
    config_radar.data.datasets[0].data[7] = radar_point.C;

    // Couleur du radar selon le score
    if (score_cvss <= 3.9) {
        config_radar.data.datasets[0].backgroundColor = color(window.chartColors.green).alpha(0.2).rgbString();
        config_radar.data.datasets[0].borderColor = window.chartColors.green;
        config_radar.data.datasets[0].pointBackgroundColor = window.chartColors.green;
    } else if (score_cvss >= 4 && score_cvss <= 6.9) {
        config_radar.data.datasets[0].backgroundColor = color(window.chartColors.yellow).alpha(0.2).rgbString();
        config_radar.data.datasets[0].borderColor = window.chartColors.yellow;
        config_radar.data.datasets[0].pointBackgroundColor = window.chartColors.yellow;
    } else if (score_cvss >= 7 && score_cvss <= 8.9) {
        config_radar.data.datasets[0].backgroundColor = color(window.chartColors.orange).alpha(0.2).rgbString();
        config_radar.data.datasets[0].borderColor = window.chartColors.orange;
        config_radar.data.datasets[0].pointBackgroundColor = window.chartColors.orange;
    } else {
        config_radar.data.datasets[0].backgroundColor = color(window.chartColors.red).alpha(0.2).rgbString();
        config_radar.data.datasets[0].borderColor = window.chartColors.red;
        config_radar.data.datasets[0].pointBackgroundColor = window.chartColors.red;
    }

    myRadar.update();
}
