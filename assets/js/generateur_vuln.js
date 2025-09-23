// generateur_vuln.js : fonctionnalités spécifiques à la page de génération de fiches de vulnérabilités

var score_cvss = 0.0;
var image;

window.chartColors = {
    red: 'rgb(255, 99, 132)',
    orange: 'rgb(255, 159, 64)',
    yellow: 'rgb(255, 205, 86)',
    green: 'rgb(162, 213, 114)',
    blue: 'rgb(54, 162, 235)'
};

var color = Chart.helpers.color;

const centerText = {
    beforeDraw: function (chart) {
        const width = chart.width
        const height = chart.height
        const ctx = chart.ctx
        ctx.restore()
        const fontSize = (height / 114).toFixed(2)
        ctx.font = 'bold ' + fontSize + 'em sans-serif'
        ctx.textBaseline = 'middle'
        ctx.fillStyle = 'white'
        ctx.strokeStyle = 'black'
        const text = score_cvss
        const textX = Math.round((width - (ctx.measureText(text).width)) / 2 - 16)
        const textY = height / 2
        ctx.fillText(text, textX, textY)
        ctx.strokeText(text, textX, textY)
        ctx.save()
    }
}

var config_radar = {
    type: 'radar',
    data: {
        labels: [
            "Integrity", "Availability", "Access vector", "Attack complexity", "Privileges required", "User interaction", "Scope", "Confidentiality"],
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
        title: {
            display: true,
            text: 'CVSS Score'
        },
        plugins: {
            legend: {
                display: false
            },
            tooltip: {
                enabled: false
            }
        },
        scales: {
            r: {
                min: -1,
                max: 2,
                ticks: {
                    display: false,
                    stepSize: 1
                }
            }
        }
    },
    plugins: [centerText]
};

var myRadar;
var c;

window.onload = function () {
    myRadar = new Chart(document.getElementById("canvas"), config_radar);
    
    // Initialize CVSS calculator
    c = new CVSS("cvssboard", {
        onchange: function () {
            window.location.hash = c.get().vector;
            c.vector.setAttribute('href', '#' + c.get().vector)
            action()
        }
    });
    
    if (window.location.hash.substring(1).length > 0) {
        c.set(decodeURIComponent(window.location.hash.substring(1)));
    }
    
    // Add event listeners for form inputs
    var step = document.getElementById("step");
    var description = document.getElementById("description");
    var impacts = document.getElementById("impacts");
    var recommandation = document.getElementById("recommandation");
    
    step.addEventListener("keyup", listener_step, false);
    description.addEventListener("keyup", listener_description, false);
    impacts.addEventListener("keyup", listener_impacts, false);
    recommandation.addEventListener("keyup", listener_recommandation, false);
};

var colorNames = Object.keys(window.chartColors);

// Event listeners for form updates
function listener_step(evt){
    var vuln_step = document.getElementById("vuln_step");
    vuln_step.innerHTML = this.value.replace(/\n\r?/g, "<br>");
}

function listener_description(evt){
    var vuln_description = document.getElementById("vuln_description");
    vuln_description.innerHTML = this.value.replace(/\n\r?/g, "<br>");
}

function listener_impacts(evt){
    var vuln_impacts = document.getElementById("vuln_impacts");
    vuln_impacts.innerHTML = this.value.replace(/\n\r?/g, "<br>");
}

function listener_recommandation(evt){
    var vuln_recommandation = document.getElementById("vuln_recommandation");
    vuln_recommandation.innerHTML = this.value.replace(/\n\r?/g, "<br>");
}

async function download(id) {
    // Store original colors and styles
    var elements = [
        { id: "vuln_description", originalColor: "", originalOpacity: "", originalClass: "" },
        { id: "vuln_step", originalColor: "", originalOpacity: "", originalClass: "" },
        { id: "vuln_impacts", originalColor: "", originalOpacity: "", originalClass: "" },
        { id: "vuln_recommandation", originalColor: "", originalOpacity: "", originalClass: "" }
    ];
    
    // Store original styles and set high contrast colors for capture
    elements.forEach(function(elem) {
        var content = document.getElementById(elem.id);
        if (content) {
            elem.originalColor = content.style.color;
            elem.originalOpacity = content.style.opacity;
            elem.originalClass = content.className;
            
            // Check if content is just placeholder text
            var isPlaceholder = content.innerHTML.includes("Enter a description") || 
                               content.innerHTML.includes("Enter steps") || 
                               content.innerHTML.includes("Enter impact") || 
                               content.innerHTML.includes("Enter recommendations") ||
                               content.innerHTML.includes("Entrez une description") || 
                               content.innerHTML.includes("Entrez les étapes") || 
                               content.innerHTML.includes("Entrez l'impact") || 
                               content.innerHTML.includes("Entrez les recommandations");
            
            if (isPlaceholder) {
                // For placeholders, use a lighter but visible color
                content.style.color = "#666666";
                content.style.opacity = "0.8";
            } else {
                // For real content, use solid black for maximum contrast
                content.style.color = "#000000";
                content.style.opacity = "1";
            }
            
            // Remove the text-white-50 class that makes text very light
            content.className = content.className.replace('text-white-50', '');
        }
    });
    
    // Also ensure background elements are visible
    var targetElement = document.getElementById(id);
    var originalBgColor = targetElement.style.backgroundColor;
    var originalBgImage = targetElement.style.backgroundImage;
    
    var a = document.createElement("a");

    await html2canvas(document.getElementById(id), {
        useCORS: true,
        allowTaint: true,
        backgroundColor: '#ffffff',
        scale: 2,  // Higher resolution
        logging: false // Disable console logs from html2canvas
    }).then((canvas) => {
        a.appendChild(canvas);
    });
    
    var b = document.createElement("a");
    b.href = a.childNodes[0].toDataURL("image/png");
    b.download = "vulnerability_sheet.png";
    b.click();
    
    // Clean up
    a.remove();
    b.remove();
    
    // Revert all original colors and styles
    elements.forEach(function(elem) {
        var content = document.getElementById(elem.id);
        if (content) {
            content.style.color = elem.originalColor || "";
            content.style.opacity = elem.originalOpacity || "";
            content.className = elem.originalClass;
        }
    });

    // Show success notification
    new Notify({
        status: 'success',
        title: 'Download successful',
        text: 'Vulnerability sheet downloaded successfully',
        effect: 'fade',
        speed: 300,
        autoclose: true,
        autotimeout: 2000,
        position: 'top right'
    });
}

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

async function copy(id) {
    // Store original colors and styles
    var elements = [
        { id: "vuln_description", originalColor: "", originalOpacity: "", originalClass: "" },
        { id: "vuln_step", originalColor: "", originalOpacity: "", originalClass: "" },
        { id: "vuln_impacts", originalColor: "", originalOpacity: "", originalClass: "" },
        { id: "vuln_recommandation", originalColor: "", originalOpacity: "", originalClass: "" }
    ];
    
    // Store original styles and set high contrast colors for capture
    elements.forEach(function(elem) {
        var content = document.getElementById(elem.id);
        if (content) {
            elem.originalColor = content.style.color;
            elem.originalOpacity = content.style.opacity;
            elem.originalClass = content.className;
            
            // Check if content is just placeholder text
            var isPlaceholder = content.innerHTML.includes("Enter a description") || 
                               content.innerHTML.includes("Enter steps") || 
                               content.innerHTML.includes("Enter impact") || 
                               content.innerHTML.includes("Enter recommendations") ||
                               content.innerHTML.includes("Entrez une description") || 
                               content.innerHTML.includes("Entrez les étapes") || 
                               content.innerHTML.includes("Entrez l'impact") || 
                               content.innerHTML.includes("Entrez les recommandations");
            
            if (isPlaceholder) {
                // For placeholders, use a lighter but visible color
                content.style.color = "#666666";
                content.style.opacity = "0.8";
            } else {
                // For real content, use solid black for maximum contrast
                content.style.color = "#000000";
                content.style.opacity = "1";
            }
            
            // Remove the text-white-50 class that makes text very light
            content.className = content.className.replace('text-white-50', '');
        }
    });

    var a = document.createElement("a");
    await html2canvas(document.getElementById(id), {
        useCORS: true,
        allowTaint: true,
        backgroundColor: '#ffffff',
        scale: 2,  // Higher resolution
        logging: false // Disable console logs from html2canvas
    }).then((canvas) => {
        a.appendChild(canvas);
    });
    
    var canvas = a.childNodes[0];
    var img = document.createElement('img');
    img.src = canvas.toDataURL('image/png')
    var div = document.createElement('div');
    div.contentEditable = true;
    div.appendChild(img);
    document.body.appendChild(div);
    
    // Copy to clipboard
    SelectText(div);
    document.execCommand('Copy');
    document.body.removeChild(div);
    
    new Notify({
        status: 'success',
        title: 'Successfully copied',
        text: 'Vulnerability sheet copied to clipboard',
        effect: 'fade',
        speed: 300,
        autoclose: true,
        autotimeout: 1500,
        position: 'top right'
    });
    
    a.remove();

    // Revert all original colors and styles
    elements.forEach(function(elem) {
        var content = document.getElementById(elem.id);
        if (content) {
            content.style.color = elem.originalColor || "";
            content.style.opacity = elem.originalOpacity || "";
            content.className = elem.originalClass;
        }
    });
}

function exporter() {
    var vuln_name = document.getElementById("name").value;
    var vuln_description = document.getElementById("description").value;
    var vuln_step = document.getElementById("step").value;
    var vuln_impacts = document.getElementById("impacts").value;
    var exploitability = document.getElementById("exploitability").innerHTML;
    var impact = document.getElementById("impact").innerHTML;
    var risk = document.getElementById("risk").innerHTML;
    var vuln_cvss = c.get().vector;
    var vuln_recommandation = document.getElementById("recommandation").value;
    var language = document.getElementById("switch").checked == false ? "EN" : "FR";
    
    var data = {
        "vuln_name": vuln_name,
        "vuln_description": vuln_description,
        "vuln_step": vuln_step,
        "vuln_impacts": vuln_impacts,
        "poc": [],
        "exploitability": exploitability,
        "impact": impact,
        "risk": risk,
        "vuln_cvss": vuln_cvss,
        "vuln_recommandation": vuln_recommandation,
        "language": language
    }
    
    vuln_name = vuln_name.replace(/\s/g, "_");
    var filename = vuln_name + ".json";
    var blob = new Blob([JSON.stringify(data)], { type: "application/json" });
    saveAs(blob, filename);
}

function importer() {
    var input = document.createElement('input');
    input.type = 'file';
    input.onchange = e => {
        var file = e.target.files[0];
        var reader = new FileReader();
        reader.readAsText(file, 'UTF-8');
        reader.onload = readerEvent => {
            var content = readerEvent.target.result;
            var data = JSON.parse(content);
            
            document.getElementById("name").value = data.vuln_name;
            document.getElementById("vuln_name").innerHTML = data.vuln_name;
            
            document.getElementById("description").value = data.vuln_description;
            document.getElementById("vuln_description").innerHTML = data.vuln_description.replace(/\n\r?/g, "<br>");
            
            document.getElementById("step").value = data.vuln_step;
            document.getElementById("vuln_step").innerHTML = data.vuln_step.replace(/\n\r?/g, "<br>");

            document.getElementById("impacts").value = data.vuln_impacts;
            document.getElementById("vuln_impacts").innerHTML = data.vuln_impacts.replace(/\n\r?/g, "<br>");

            document.getElementById("exploitability").innerHTML = data.exploitability;
            document.getElementById("impact").innerHTML = data.impact;
            document.getElementById("risk").innerHTML = data.risk;

            if (data.language == "EN") {
                document.getElementById("switch").checked = false;
            } else {
                document.getElementById("switch").checked = true;
            }

            change_language();
            c.set(data.vuln_cvss);

            document.getElementById("recommandation").value = data.vuln_recommandation;
            document.getElementById("vuln_recommandation").innerHTML = data.vuln_recommandation.replace(/\n\r?/g, "<br>");
        }
    }
    input.click();
}

function saveAs(blob, filename) {
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = filename || 'download';
    var clickHandler = function () {
        setTimeout(function () {
            URL.revokeObjectURL(url);
            this.removeEventListener('click', clickHandler);
        }, 150);
    };
    a.addEventListener('click', clickHandler, false);
    a.click();
    return a;
}

function change_language() {
    if (!document.getElementById("switch").checked) {
        if (document.getElementById("name").value == "") {
            document.getElementById("vuln_name").innerHTML = "Vulnerability Name";
        }
        document.getElementById("description_title").innerHTML = "Description:";
        document.getElementById("step_title").innerHTML = "Steps to Reproduce:";
        document.getElementById("impact_title").innerHTML = "Impact:";
        document.getElementById("evaluation_title").innerHTML = "Risk Evaluation:";
        document.getElementById("exploitability_table").innerHTML = "Exploitability";
        document.getElementById("impact_table").innerHTML = "Impact";
        document.getElementById("risk_table").innerHTML = "Risk";
        document.getElementById("cvss_title").innerHTML = "CVSS 3.1 Evaluation:";
        document.getElementById("recommandation_title").innerHTML = "Recommendations:";
        
        var labels = ["Integrity", "Availability", "Access vector", "Attack complexity", "Privileges required", "User interaction", "Scope", "Confidentiality"];
        myRadar.data.labels = labels;
    } else {
        if (document.getElementById("name").value == "") {
            document.getElementById("vuln_name").innerHTML = "Nom de la vulnérabilité";
        }
        document.getElementById("description_title").innerHTML = "Description :";
        document.getElementById("step_title").innerHTML = "Étapes de reproduction :";
        document.getElementById("impact_title").innerHTML = "Impact :";
        document.getElementById("evaluation_title").innerHTML = "Évaluation du risque :";
        document.getElementById("exploitability_table").innerHTML = "Exploitabilité";
        document.getElementById("impact_table").innerHTML = "Impact";
        document.getElementById("risk_table").innerHTML = "Risque";
        document.getElementById("cvss_title").innerHTML = "Évaluation CVSS 3.1 :";
        document.getElementById("recommandation_title").innerHTML = "Recommandations :";
        
        var labels = ["Intégrité", "Disponibilité", "Vecteur d'accès", "Complexité", "Privilèges requis", "Interaction", "Portée", "Confidentialité"];
        myRadar.data.labels = labels;
    }
    action();
}

function fill_vuln() {
    var name = document.getElementById("name").value;
    document.getElementById("vuln_name").innerHTML = name || (document.getElementById("switch").checked ? "Nom de la vulnérabilité" : "Vulnerability Name");
    
    var description = document.getElementById("description").value;
    document.getElementById("vuln_description").innerHTML = description.replace(/\n\r?/g, "<br>") || (document.getElementById("switch").checked ? "Entrez une description ci-dessus" : "Enter a description above");
    
    var step = document.getElementById("step").value;
    document.getElementById("vuln_step").innerHTML = step.replace(/\n\r?/g, "<br>") || (document.getElementById("switch").checked ? "Entrez les étapes ci-dessus" : "Enter steps above");
    
    var impacts = document.getElementById("impacts").value;
    document.getElementById("vuln_impacts").innerHTML = impacts.replace(/\n\r?/g, "<br>") || (document.getElementById("switch").checked ? "Entrez l'impact ci-dessus" : "Enter impact above");
    
    var recommandation = document.getElementById("recommandation").value;
    document.getElementById("vuln_recommandation").innerHTML = recommandation.replace(/\n\r?/g, "<br>") || (document.getElementById("switch").checked ? "Entrez les recommandations ci-dessus" : "Enter recommendations above");
}

function action() {
    console.clear();
    var tmp = c.get().vector.split("/");
    var score = { "AV": 0, "AC": 0, "PR": 0, "UI": 0, "S": 0, "C": 0, "I": 0, "A": 0 };
    var radar_point = { "AV": 0, "AC": 0, "PR": 0, "UI": 0, "S": 0, "C": 0, "I": 0, "A": 0 };
    
    for (let index = 1; index < tmp.length; index++) {
        var type = tmp[index].split(":")[0];
        var selection = tmp[index].split(":")[1];
        
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

    // Calculate PR score based on scope
    if (score["S"] == 6.42) {
        switch (score["PR"]) {
            case "N": score["PR"] = 0.85; break;
            case "L": score["PR"] = 0.62; break;
            case "H": score["PR"] = 0.27; break;
        }
    } else {
        switch (score["PR"]) {
            case "N": score["PR"] = 0.85; break;
            case "L": score["PR"] = 0.68; break;
            case "H": score["PR"] = 0.5; break;
        }
    }

    score_cvss = c.get().score;

    // Calculate impact and exploitability
    var impact = 1 - (1 - score["C"]) * (1 - score["I"]) * (1 - score["A"])
    if (score["S"] == 6.42) {
        impact = 6.42 * impact;
    } else {
        impact = 7.52 * (impact - 0.029) - 3.25 * Math.pow((impact - 0.02), 15);
    }

    var exploitability = 8.22 * score["AV"] * score["AC"] * score["PR"] * score["UI"];

    impact = Math.round(impact * 10) / 10
    var impact_metric = impact;

    // Determine impact level
    if (impact <= 2.5) {
        impact = !document.getElementById("switch").checked ? "Minor" : "Mineur";
        document.getElementById("impact").style.color = window.chartColors.green;
    } else if (impact > 2.5 && impact <= 4) {
        impact = "Important";
        document.getElementById("impact").style.color = window.chartColors.yellow;
    } else if (impact > 4 && impact <= 5.5) {
        impact = !document.getElementById("switch").checked ? "Major" : "Majeur";
        document.getElementById("impact").style.color = window.chartColors.orange;
    } else {
        impact = !document.getElementById("switch").checked ? "Critical" : "Critique";
        document.getElementById("impact").style.color = window.chartColors.red;
    }

    document.getElementById("impact").innerHTML = impact + " " + impact_metric;

    exploitability = Math.round(exploitability * 10) / 10;
    var exploitability_metric = exploitability;

    if (score["S"] == 6.42 && exploitability == 4) {
        exploitability = exploitability - 1;
    }

    var virt_exploitability = exploitability;

    // Determine exploitability level
    if (exploitability <= 1) {
        exploitability = !document.getElementById("switch").checked ? "Very hard" : "Difficile";
        document.getElementById("exploitability").style.color = window.chartColors.green;
    } else if (exploitability > 1 && exploitability <= 2) {
        exploitability = !document.getElementById("switch").checked ? "Hard" : "Elevée";
        document.getElementById("exploitability").style.color = window.chartColors.yellow;
    } else if (exploitability > 2 && exploitability <= 3) {
        exploitability = !document.getElementById("switch").checked ? "Medium" : "Moyen";
        document.getElementById("exploitability").style.color = window.chartColors.orange;
    } else {
        exploitability = !document.getElementById("switch").checked ? "Easy" : "Facile";
        document.getElementById("exploitability").style.color = window.chartColors.red;
    }

    document.getElementById("exploitability").innerHTML = exploitability + " " + exploitability_metric;

    // Risk matrix calculation
    const risk_matrix_fr = {
        "Mineur": { "Difficile": "Mineur", "Elevée": "Mineur", "Moyen": "Important", "Facile": "Important" },
        "Important": { "Difficile": "Mineur", "Elevée": "Important", "Moyen": "Important", "Facile": "Majeur" },
        "Majeur": { "Difficile": "Important", "Elevée": "Important", "Moyen": "Majeur", "Facile": "Critique" },
        "Critique": { "Difficile": "Important", "Elevée": "Majeur", "Moyen": "Critique", "Facile": "Critique" }
    };
    
    const risk_matrix_en = {
        "Minor": { "Very hard": "Minor", "Hard": "Minor", "Medium": "Important", "Easy": "Important" },
        "Important": { "Very hard": "Minor", "Hard": "Important", "Medium": "Important", "Easy": "Major" },
        "Major": { "Very hard": "Important", "Hard": "Important", "Medium": "Major", "Easy": "Critical" },
        "Critical": { "Very hard": "Important", "Hard": "Major", "Medium": "Critical", "Easy": "Critical" }
    };

    var risk_matrix = !document.getElementById("switch").checked ? risk_matrix_en : risk_matrix_fr;
    var risk = risk_matrix[impact][exploitability];

    document.getElementById("risk").innerHTML = risk;
    
    if (risk == "Mineur" || risk == "Minor") {
        document.getElementById("risk").style.color = window.chartColors.green;
    } else if (risk == "Important") {
        document.getElementById("risk").style.color = window.chartColors.yellow;
    } else if (risk == "Majeur" || risk == "Major") {
        document.getElementById("risk").style.color = window.chartColors.orange;
    } else {
        document.getElementById("risk").style.color = window.chartColors.red;
    }

    // Update radar chart
    config_radar.data.datasets[0].data[0] = radar_point["I"];
    config_radar.data.datasets[0].data[1] = radar_point["A"];
    config_radar.data.datasets[0].data[2] = radar_point["AV"];
    config_radar.data.datasets[0].data[3] = radar_point["AC"];
    config_radar.data.datasets[0].data[4] = radar_point["PR"];
    config_radar.data.datasets[0].data[5] = radar_point["UI"];
    config_radar.data.datasets[0].data[6] = radar_point["S"];
    config_radar.data.datasets[0].data[7] = radar_point["C"];

    // Update chart colors based on CVSS score
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
