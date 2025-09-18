// commands.js : logique spécifique à la page de cheat sheet/commandes

// Chargement des polices WebFont
WebFont.load({
    google: { families: ["Lato:300,400,700,900"] },
    custom: {
        families: [
            "Flaticon",
            "Font Awesome 5 Solid",
            "Font Awesome 5 Regular",
            "Font Awesome 5 Brands",
            "simple-line-icons",
        ],
        urls: ["./assets/css/fonts.min.css"],
    },
    active: function () {
        sessionStorage.fonts = true;
    },
});

// Colorisation dynamique des badges selon l'outil
window.onload = function () {
    data.forEach(element => {
        if (element.tool === "linux") {
            element.color = "#f1c40f"
        } else if (element.tool === "windows") {
            element.color = "#3498db"
        } else if (element.tool === "docker") {
            element.color = "#9b59b6"
        } else if (element.tool === "powershell") {
            element.color = "#e74c3c"
        } else if (element.tool === "sqlmap") {
            element.color = "#2ecc71"
        } else if (element.tool === "Metasploit - msf") {
            element.color = "#e67e22"
        } else if (element.tool === "nmap") {
            element.color = "#93e0e8"
        } else if (element.tool === "masscan") {
            element.color = "#cbc5ae"
        } else if (element.tool === "wifi") {
            element.color = "#f99757"
        } else if (element.tool === "msfvenom") {
            element.color = "#21701a"
        } else if (element.tool === "NetExec") {
            element.color = "##7bccf7"
        } else if (element.tool === "kerbrute") {
            element.color = "#4e786a"
        } else if (element.tool === "SCShell") {
            element.color = "#913e2e"
        } else if (element.tool === "chisel") {
            element.color = "#f7f7f7"
        } else if (element.tool === "Compile") {
            element.color = "#b198d2"
        } else if (element.tool === "ffuf") {
            element.color = "#af1c75"
        } else if (element.tool === "grep hash") {
            element.color = "#f46c06"
        } else if (element.tool === "socat") {
            element.color = "#f80000"
        } else if (element.tool === "mimikatz") {
            element.color = "#ffccda"
        } else if (element.tool === "JwtTool") {
            element.color = "#cdffb2"
        } else if (element.tool === "linux bash") {
            element.color = "#cdffb2"
        } else if (element.tool === "Others grep") {
            element.color = "#eefc9f"
        } else if (element.tool === "procdump") {
            element.color = "#ecfc94"
        } else if (element.tool === "WPSCAN") {
            element.color = "#889fe8"
        } else if (element.tool === "impacket") {
            element.color = "#ddfc80"
        } else if (element.tool === "ntfs") {
            element.color = "#74fc76"
        } else if (element.tool === "coercer") {
            element.color = "#7695f2"
        }
        $("#add-row").dataTable().fnAddData([
            element.category,
            `<span class="badge" style="font-weight: bold; border: 1px solid ${element.color}; background-color: transparent; color: ${element.color}">${element.tool}</span>`,
            element.information,
            element.command,
            `
            <div class="form-button-action">
                <button type="button" data-toggle="tooltip" title="" class="btn btn-link btn-primary btn-lg"
                    data-original-title="Open command" onclick="inspect(${element.id})">
                    <i class="fas fa-eye"></i>
                </button>
                <button type="button" data-toggle="tooltip" title="" class="btn btn-link btn-success"
                    data-original-title="Copy command" onclick="copy(${element.id})">
                    <i class="fas fa-copy"></i>
                </button>
            </div>
            `
        ]);
    });
    //order by sub category
    $('#add-row').DataTable().order([1, 'asc']).draw();
}

// Initialisation du syntax highlighting
document.addEventListener('DOMContentLoaded', function() {
    hljs.highlightAll();
});

// Fonction de nettoyage des paramètres
function clean() {
    var elements = document.getElementsByClassName('parameters');
    while (elements.length > 0) {
        // remove event listener
        elements[0].querySelector('input').removeEventListener('keyup', function () { });
        elements[0].parentNode.removeChild(elements[0]);
    }
}

// Fonction d'inspection d'une commande
function inspect(id) {
    const escapeHTML = (str) => {
        return str.replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
    };

    clean();
    var command = data.find(x => x.id == id);
    var code = document.getElementById('code');
    var category = document.getElementById('category');
    var tool = document.getElementById('tool');
    var information = document.getElementById('information');
    var copyBtn = document.getElementById('copyBtn');

    var link = document.getElementById('link'); 
    if (link) {
        link.remove();
    }

    if (command.link) {
        var balise = document.createElement('p');
        balise.innerHTML = "Link to the tool: ";
        balise.id = "link";
        var linka = document.createElement('a');

        linka.onmouseover = function () {
            linka.style = "color: #6861ce;";
        }
        linka.onmouseout = function () {
            linka.style = "color: white; text-decoration: underline;";
        }

        balise.appendChild(linka);
        linka.href = command.link;
        linka.innerHTML = command.link;
        linka.target = "_blank";
        linka.style = "color: white; text-decoration: underline;"
        document.getElementById('command_div').prepend(balise);
    }

    // if there is [parameters] in the command create an input text for each parameters 
    if (command.command) {
        var command_div = document.getElementById('command_div');
        var parameters = command.command.match(/\[.*?\]/g);
        var map_parameters = {};

        if (parameters) {
            parameters.forEach(parameter => {
                var div = document.createElement('div');
                div.className = "parameters input-group mb-3";

                var name_parameter = document.createElement('h3');
                name_parameter.style = "width: 50%;"
                name_parameter.className = "input-group-text";
                
                var default_parameter = parameter.match(/\[.*?\|.*?\]/g);
                if (default_parameter) {
                    name_parameter.innerHTML = default_parameter[0].replace("[", "").replace("]", "").split("|")[0];
                } else {
                    name_parameter.innerHTML = parameter.replace("[", "").replace("]", "");
                }
                div.appendChild(name_parameter);

                var input = document.createElement('input');
                var origin_code = command.command;
                
                input.value = default_parameter ? default_parameter[0].replace("[", "").replace("]", "").split("|")[1] : "";
                map_parameters[name_parameter.innerHTML] = input.value;
                
                input.type = "text";
                input.className = "form-control";
                div.appendChild(input);
                command_div.insertBefore(div, document.getElementById('CopyDiv'));
                
                input.addEventListener("keyup", function(event) {
                    map_parameters[name_parameter.innerHTML] = this.value;
                    var code = origin_code;
                    Object.keys(map_parameters).forEach(key => {
                        if (map_parameters[key] != "") {
                            code = code.replace(new RegExp("\\["+key+"([^\\]]*)\\]"), map_parameters[key]);
                        }
                    });
                    document.getElementById("code").innerHTML = escapeHTML(code);                   
                }, false);
            });               
        }
    }
    var origin_code = command.command;
    for (var key in map_parameters) {
        if (map_parameters[key] != "") {
            origin_code = origin_code.replace(new RegExp("\\["+key+"([^\\]]*)\\]"), map_parameters[key]);
        }
    }
    code.innerHTML = origin_code;
    category.innerHTML = command.category;
    tool.style = `font-weight: bold; border: 1px solid ${command.color}; background-color: transparent; color: ${command.color}`;
    tool.innerHTML = command.tool;
    information.innerHTML = command.information;
    copyBtn.setAttribute('onclick', `copy(${id})`);

    $('#openCommand').modal('show');
}

// Fonction de copie d'une commande
function copy(id) {
    var command = data.find(x => x.id == id);
    var code = document.getElementById('code').innerText
    var input = document.getElementsByTagName('input')[0];
    var old_value = input.value;
    input.value = code;
    input.select();
    document.execCommand('copy');
    input.value = old_value;
    new Notify({
        status: 'success',
        title: 'Command copied',
        text: '',
        effect: 'fade',
        speed: 300,
        customClass: '',
        customIcon: '',
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
