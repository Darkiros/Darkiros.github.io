// project.js : fonctionnalités spécifiques à la page de gestion de projet

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
        maintainAspectRatio: false,
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
                },
                grid: {
                    color: 'rgba(255, 255, 255, 0.2)'
                },
                angleLines: {
                    color: 'rgba(255, 255, 255, 0.2)'
                },
                pointLabels: {
                    color: 'white',
                    font: {
                        size: 11
                    }
                }
            }
        }
    },
    plugins: [centerText]
};

var myRadar;
var vulnerabilityTable;

// Initialization when page loads
window.onload = function () {
    try {
        // Language setup
        if (localStorage.getItem('language') == 'FR') {
            document.getElementById('switch').checked = true;
        } else {
            localStorage.setItem('language', 'EN');
            document.getElementById('switch').checked = false;
        }
        change_language();

        var list_vuln = JSON.parse(localStorage.getItem('list_vuln'));

        // Initialize radar chart if canvas exists
        const canvas = document.getElementById("canvas");
        if (canvas) {
            myRadar = new Chart(canvas, config_radar);
        }
        
        // Initialize DataTable
        vulnerabilityTable = $('#add-row').DataTable({
            "pageLength": 10,
            "lengthMenu": [
                [10, 25, 50, -1],
                [10, 25, 50, "All"]
            ],
            "columnDefs": [
                {
                    "targets": 2, // Description
                    "render": function (data, type, row) {
                        var maxWords = 15;
                        var wordsArray = data.split(' ');
                        if (wordsArray.length > maxWords) {
                            return wordsArray.slice(0, maxWords).join(' ') + '...';
                        }
                        return data;
                    }
                }
            ],
            responsive: true,
            "language": {
                "search": "Search vulnerabilities:",
                "lengthMenu": "Show _MENU_ vulnerabilities per page",
                "info": "Showing _START_ to _END_ of _TOTAL_ vulnerabilities",
                "paginate": {
                    "first": "First",
                    "last": "Last",
                    "next": "Next",
                    "previous": "Previous"
                }
            }
        });

        // Project name setup
        const project_name = localStorage.getItem('project_name');
        if (project_name) {
            document.getElementById("title").innerHTML = project_name;
            document.getElementById("project_name").value = project_name;
        }

        // Load vulnerabilities
        loadVulnerabilities();

        // Setup other fields from localStorage
        setupFormFields();

        // Setup CVSS board
        initializeCVSSBoard();

        // Setup event listeners
        setupEventListeners();

    } catch (error) {
        console.error("Initialization error:", error);
        swal({
            title: "Error",
            text: "An error occurred when loading the application. The local storage will be cleared.",
            icon: "error",
        }).then(() => {
            localStorage.clear();
            location.reload();
        });
    }
};

// Load vulnerabilities from localStorage
function loadVulnerabilities() {
    var list_vuln = JSON.parse(localStorage.getItem('list_vuln'));
    
    if (list_vuln && list_vuln.length > 0) {
        // Clear existing rows
        vulnerabilityTable.clear();
        
        list_vuln.forEach(vuln => {
            vuln.description = vuln.description.replace(/\n/g, "<br>");
            addRowToTable(vuln);
        });
        
        vulnerabilityTable.draw();
        updateCVSSColors();
    } else {
        localStorage.setItem('list_vuln', JSON.stringify([]));
    }
}

// Add row to vulnerability table
function addRowToTable(vuln) {
    const actionButtons = `
        <div class="form-button-action">
            <button type="button" data-toggle="tooltip" title="Edit" class="btn btn-link btn-primary btn-lg" 
                    onclick="edit('${vuln.id}')">
                <i class="fa fa-edit"></i>
            </button>
            <button type="button" data-toggle="tooltip" title="Remove" class="btn btn-link btn-danger" 
                    onclick="removeVuln('${vuln.id}')">
                <i class="fa fa-times"></i>
            </button>
        </div>
    `;

    vulnerabilityTable.row.add([
        vuln.name || '',
        vuln.severity || '',
        vuln.description || '',
        vuln.score || '0.0',
        actionButtons
    ]);
}

// Update CVSS colors in table
function updateCVSSColors() {
    var list_vuln = JSON.parse(localStorage.getItem('list_vuln')) || [];
    var cvss_color = list_vuln.map(vuln => {
        const score = parseFloat(vuln.score) || 0;
        if (score <= 3.9) return "green";
        else if (score <= 6.9) return "yellow";
        else if (score <= 8.9) return "orange";
        else return "red";
    });

    // Apply colors to table rows
    vulnerabilityTable.rows().every(function(rowIdx, tableLoop, rowLoop) {
        if (cvss_color[rowIdx]) {
            const scoreCell = this.node().cells[3];
            if (scoreCell) {
                scoreCell.style.color = cvss_color[rowIdx];
                scoreCell.style.fontWeight = 'bold';
            }
        }
    });
}

// Setup form fields from localStorage
function setupFormFields() {
    if (localStorage.getItem('pentester')) {
        document.getElementById('pentester').value = localStorage.getItem('pentester');
    } else {
        localStorage.setItem('pentester', "");
    }

    if (localStorage.getItem('dateFrom')) {
        document.getElementById('dateFrom').value = localStorage.getItem('dateFrom');
    } else {
        document.getElementById('dateFrom').value = new Date().toISOString().split('T')[0];
        localStorage.setItem('dateFrom', document.getElementById('dateFrom').value);
    }

    if (localStorage.getItem('dateTo')) {
        document.getElementById('dateTo').value = localStorage.getItem('dateTo');
    } else {
        document.getElementById('dateTo').value = new Date().toISOString().split('T')[0];
        localStorage.setItem('dateTo', document.getElementById('dateTo').value);
    }
}

// Initialize CVSS board
function initializeCVSSBoard() {
    try {
        if (typeof CVSS31 !== 'undefined') {
            const cvssElement = document.getElementById("cvssboard");
            if (cvssElement) {
                cvssElement.innerHTML = CVSS31.renderToText();
            }
        }
    } catch (error) {
        console.log("CVSS board initialization error:", error);
    }
}

// Setup event listeners
function setupEventListeners() {
    // Auto-save project data when inputs change
    const projectNameInput = document.getElementById('project_name');
    const pentesterInput = document.getElementById('pentester');
    
    if (projectNameInput) {
        projectNameInput.addEventListener('change', saveProjectData);
        projectNameInput.addEventListener('input', function() {
            document.getElementById("title").innerHTML = this.value || "Project Management";
        });
    }
    
    if (pentesterInput) {
        pentesterInput.addEventListener('change', saveProjectData);
    }

    // Add vulnerability button
    const addButton = document.getElementById('addRowButton');
    if (addButton) {
        addButton.addEventListener('click', function() {
            addNewVulnerability();
        });
    }
}

// Language change function
function change_language() {
    if (document.getElementById('switch').checked) {
        localStorage.setItem('language', 'FR');
        updateLabelsToFrench();
        config_radar.data.labels = [
            "Intégrité", "Disponibilité", "Vecteur d'accès", "Complexité", "Privilèges requis", "Interaction", "Portée", "Confidentialité"
        ]
    } else {
        localStorage.setItem('language', 'EN');
        updateLabelsToEnglish();
        config_radar.data.labels = [
            "Integrity", "Availability", "Access vector", "Attack complexity", "Privileges required", "User interaction", "Scope", "Confidentiality"
        ]
    }
    try {
        if (myRadar) {
            myRadar.update();
        }
        updateCVSSBoard();
    } catch (error) {
        console.log("CVSS board not found");
    }
}

function updateLabelsToFrench() {
    const elements = {
        'description_title': "Description :",
        'step_title': "Étapes pour reproduire :",
        'impact_title': "Impacts :",
        'evaluation_title': "Évaluation du risque :",
        'cvss_title': "Évaluation CVSS 3.1 :",
        'recommandation_title': "Recommandations :",
        'exploitability_table': "Exploitabilité",
        'impact_table': "Impact",
        'risk_table': "Risque"
    };
    
    for (const [id, text] of Object.entries(elements)) {
        const element = document.getElementById(id);
        if (element) element.innerHTML = text;
    }
}

function updateLabelsToEnglish() {
    const elements = {
        'description_title': "Description:",
        'step_title': "Steps to reproduce:",
        'impact_title': "Impact:",
        'evaluation_title': "Risk evaluation:",
        'cvss_title': "CVSS 3.1 Evaluation:",
        'recommandation_title': "Recommendations:",
        'exploitability_table': "Exploitability",
        'impact_table': "Impact",
        'risk_table': "Risk"
    };
    
    for (const [id, text] of Object.entries(elements)) {
        const element = document.getElementById(id);
        if (element) element.innerHTML = text;
    }
}

// Add new vulnerability
function addNewVulnerability() {
    const name = document.getElementById("name").value;
    const severity = document.getElementById("severity").value;
    const description = document.getElementById("description").value;
    const score = document.getElementById("score").value || "0.0";

    if (!name) {
        swal("Error", "Please enter a vulnerability name", "error");
        return;
    }

    const vulnerability = {
        id: generateUniqueId(),
        name: name,
        severity: severity,
        description: description,
        score: score
    };

    // Add to localStorage
    let list_vuln = JSON.parse(localStorage.getItem('list_vuln')) || [];
    list_vuln.push(vulnerability);
    localStorage.setItem('list_vuln', JSON.stringify(list_vuln));

    // Add to table
    addRowToTable(vulnerability);
    vulnerabilityTable.draw();
    updateCVSSColors();

    // Close modal and clean form
    $('#addRowModal').modal('hide');
    clean();

    swal("Success!", "Vulnerability added successfully.", "success");
}

// Generate unique ID
function generateUniqueId() {
    return 'vuln_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

// Validation functions
function validateDate() {
    const dateFrom = new Date(document.getElementById('dateFrom').value);
    const dateTo = new Date(document.getElementById('dateTo').value);
    
    if (dateFrom > dateTo) {
        swal("Invalid date range", "Start date cannot be after end date", "error");
        return false;
    }
    
    localStorage.setItem('dateFrom', document.getElementById('dateFrom').value);
    localStorage.setItem('dateTo', document.getElementById('dateTo').value);
    return true;
}

// Save project data
function saveProjectData() {
    const projectName = document.getElementById('project_name').value;
    const pentester = document.getElementById('pentester').value;
    
    if (projectName) {
        localStorage.setItem('project_name', projectName);
        document.getElementById("title").innerHTML = projectName;
    }
    
    if (pentester) {
        localStorage.setItem('pentester', pentester);
    }
}

// Clean form
function clean() {
    const fields = ['name', 'description', 'score'];
    fields.forEach(field => {
        const element = document.getElementById(field);
        if (element) element.value = "";
    });
    
    const severity = document.getElementById("severity");
    if (severity) severity.selectedIndex = 0;
    
    score_cvss = 0.0;
    updateCVSSDisplay();
}

// Remove vulnerability
function removeVuln(id) {
    swal({
        title: "Are you sure?",
        text: "You won't be able to revert this!",
        type: "warning",
        buttons: {
            confirm: {
                text: "Yes, delete it!",
                className: "btn btn-success",
            },
            cancel: {
                visible: true,
                className: "btn btn-danger",
            },
        },
    }).then((Delete) => {
        if (Delete) {
            var list_vuln = JSON.parse(localStorage.getItem('list_vuln'));
            list_vuln = list_vuln.filter(vuln => vuln.id !== id);
            localStorage.setItem('list_vuln', JSON.stringify(list_vuln));
            
            swal({
                title: "Deleted!",
                text: "Your vulnerability has been deleted.",
                type: "success",
                buttons: {
                    confirm: {
                        className: "btn btn-success",
                    },
                },
            }).then(() => {
                location.reload();
            });
        }
    });
}

// Edit vulnerability (simplified)
function edit(id) {
    const list_vuln = JSON.parse(localStorage.getItem('list_vuln'));
    const vuln = list_vuln.find(v => v.id === id);
    
    if (vuln) {
        document.getElementById("name").value = vuln.name;
        document.getElementById("severity").value = vuln.severity;
        document.getElementById("description").value = vuln.description;
        document.getElementById("score").value = vuln.score;
        
        // Remove the vulnerability temporarily
        const filteredVulns = list_vuln.filter(v => v.id !== id);
        localStorage.setItem('list_vuln', JSON.stringify(filteredVulns));
        
        $('#addRowModal').modal('show');
    }
}

// Update CVSS display
function updateCVSSDisplay() {
    const scoreElement = document.getElementById('score');
    if (scoreElement) {
        scoreElement.value = score_cvss;
    }
    
    if (myRadar) {
        myRadar.data.datasets[0].data = [1, 1, 1, 1, 1, 1, 1, 1];
        myRadar.update();
    }
}

// Update CVSS board
function updateCVSSBoard() {
    try {
        if (typeof CVSS31 !== 'undefined') {
            const cvssElement = document.getElementById("cvssboard");
            if (cvssElement) {
                cvssElement.innerHTML = CVSS31.renderToText();
            }
        }
    } catch (error) {
        console.log("CVSS board update error:", error);
    }
}

// Export/Import functions
function exporter() {
    const projectData = {
        project_name: localStorage.getItem('project_name') || '',
        pentester: localStorage.getItem('pentester') || '',
        dateFrom: localStorage.getItem('dateFrom') || '',
        dateTo: localStorage.getItem('dateTo') || '',
        list_vuln: JSON.parse(localStorage.getItem('list_vuln') || '[]'),
        language: localStorage.getItem('language') || 'EN'
    };
    
    const dataStr = JSON.stringify(projectData, null, 2);
    const dataBlob = new Blob([dataStr], {type: 'application/json'});
    
    const link = document.createElement('a');
    link.href = URL.createObjectURL(dataBlob);
    link.download = `project_${projectData.project_name || 'export'}_${new Date().toISOString().split('T')[0]}.json`;
    link.click();
    
    swal("Success!", "Project exported successfully.", "success");
}

function importer() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    
    input.onchange = function(event) {
        const file = event.target.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = function(e) {
                try {
                    const projectData = JSON.parse(e.target.result);
                    
                    // Restore data to localStorage
                    for (const [key, value] of Object.entries(projectData)) {
                        if (key === 'list_vuln') {
                            localStorage.setItem(key, JSON.stringify(value));
                        } else {
                            localStorage.setItem(key, value);
                        }
                    }
                    
                    swal({
                        title: "Success!",
                        text: "Project imported successfully.",
                        type: "success",
                        buttons: {
                            confirm: {
                                className: "btn btn-success",
                            },
                        },
                    }).then(() => {
                        location.reload();
                    });
                    
                } catch (error) {
                    swal("Error", "Invalid project file format.", "error");
                }
            };
            reader.readAsText(file);
        }
    };
    
    input.click();
}

// Generate DOCX (simplified version)
function generateDocx() {
    swal({
        title: "Feature coming soon!",
        text: "DOCX generation will be available in a future update.",
        type: "info",
        buttons: {
            confirm: {
                className: "btn btn-info",
            },
        },
    });
}

// Utility functions
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
