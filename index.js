// server.js
const YAML = require('yaml');
const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const cors = require('cors')
const os = require('os');
const app = express();
const readline = require('readline');
const PORT = 3030;


const { exec } = require('child_process')

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors()); // Para permitir peticiones desde el frontend

const configFilePath = '/etc/config.json'; // Archivo único de configuración
const logFilePath = '/var/log/syslog';
const netplanConfigPath = '/etc/netplan/50-cloud-init.yaml';

// let lastLogPosition = 0; // Variable para rastrear la última posición leída
// let sentLogs = []; // Para almacenar las entradas de log que ya se han enviado


async function generateConfigFile() {
    try {
        // Leer archivo template /etc/template_config.json
        const configTemplate = JSON.parse(fs.readFileSync('/etc/template_config.json', 'utf-8'));

        // Escribir el archivo de configuración
        fs.writeFileSync(configFilePath, JSON.stringify(configTemplate, null, 2));

        console.log('Archivo de configuración generado correctamente.');
    } catch (error) {
        console.error('Error generando archivo de configuración:', error);
    }
}


function generateNetplanConfig(config) {
    const netplan = {
        network: {
            version: 2,
            ethernets: {},
            wifis: {},
        },
    };

    config.interfaces.forEach((iface) => {
        if (iface.type === "ethernet") {
            netplan.network.ethernets[iface.name] = {
                dhcp4: iface.method === "dhcp",
                addresses: iface.method === "static" ? [config.ipAddress] : undefined,
                routes: iface.method === "static" ? [{ to: "default", via: config.gateway }] : undefined,
                nameservers: iface.method === "static" ? { addresses: [...config.dns] } : undefined,
            };
        } else if (iface.type === "wifi") {
            netplan.network.wifis[iface.name] = {
                dhcp4: iface.method === "dhcp",
                optional: true,
                "access-points": {
                    [((iface.ssid != null && iface.ssid != '') ? iface.ssid : 'NOSSID')]: {
                        password: iface.password,
                    },
                },
                addresses: iface.method === "static" ? [config.ipAddress] : undefined,
                routes: iface.method === "static" ? [{ to: "default", via: config.gateway }] : undefined,
                nameservers: iface.method === "static" ? { addresses: [...config.dns] } : undefined,
            };
        }
    });

    return YAML.stringify(netplan);
}


function applyNetplanConfig(config) {
    const yamlConfig = generateNetplanConfig(config);

    // Escribir el archivo de configuración
    fs.writeFileSync(netplanConfigPath, yamlConfig);

    // Aplicar la nueva configuración
    exec('sudo netplan apply', (error) => {
        if (error) {
            console.error('Error aplicando configuración de Netplan:', error);
            throw new Error('Error aplicando configuración de Netplan');
        }
    });
}


// // Ruta para acceder a los logs en tiempo real
// app.get('/sys-logs', (req, res) => {
//     res.setHeader('Content-Type', 'text/event-stream');
//     res.setHeader('Cache-Control', 'no-cache');
//     res.setHeader('Connection', 'keep-alive');
//     lastLogPosition = 0;
//     sentLogs = []

//     sendLogs(res, null, 'wireguard:');
//     // Aquí puedes usar setInterval o algún otro mecanismo para comprobar cambios
//     const intervalId = setInterval(() => {
//         getLogEntry(res, null, 'wireguard:');
//     }, 1000); // Cambia la frecuencia según tus necesidades

//     // Limpia el intervalo al cerrar la conexión
//     req.on('close', () => {
//         clearInterval(intervalId);
//         res.end();
//     });
// });

app.get('/sys-logs', (req, res) => {

    // Configuración de headers para Server-Sent Events (SSE)
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    let lastLogPosition = 0;
    let logData = '';
    const sentLogs = [];

    const sendLogUpdate = () => {
        fs.stat(logFilePath, (err, stats) => {
            if (err) {
                console.error('Error al obtener información del archivo de logs:', err);
                return;
            }

            if (stats.size > lastLogPosition) {
                const logStream = fs.createReadStream(logFilePath, {
                    start: lastLogPosition,
                    end: stats.size
                });

                logStream.on('data', (chunk) => {
                    logData += chunk;
                });

                logStream.on('end', () => {
                    const logEntries = logData.split('\n').filter(Boolean).filter(e => !e.includes('wireguard:'));  // Dividir en líneas y eliminar vacías
                    lastLogPosition = stats.size;  // Actualizar la posición para leer solo nuevos logs

                    logEntries.forEach((entry) => {
                        if (!sentLogs.includes(entry)) {
                            res.write(`data: ${entry}\n\n`);  // Enviar cada línea de log al cliente
                            sentLogs.push(entry);
                        }
                    });

                    logData = '';  // Limpiar la variable después de enviar
                });

                logStream.on('error', (error) => {
                    console.error('Error al leer el archivo de logs:', error);
                });
            }
        });
    };

    // Enviar logs cada 3 segundos
    const intervalId = setInterval(() => {
        sendLogUpdate();
    }, 3000);

    // Manejar cierre de la conexión
    req.on('close', () => {
        console.log('Conexión cerrada por el cliente.');
        clearInterval(intervalId);
        res.end();
    });
});

// Endpoint para iniciar/detener VirtualHere
app.get('/virtualhere/:action', (req, res) => {
    const action = req.params['action'];

    if (action === 'start') {
        exec('sudo pm2 start dev-share-server', (error, stdout, stderr) => {
            if (error) {
                console.error(`Error: ${stderr}`);
                return res.status(500).json({ message: 'Error al iniciar VirtualHere.' });
            }
            res.json({ message: 'VirtualHere ha sido iniciado.' });
        });
    } else if (action === 'stop') {
        exec('sudo pm2 stop dev-share-server', (error, stdout, stderr) => {
            if (error) {
                console.error(`Error: ${stderr}`);
                return res.status(500).json({ message: 'Error al detener VirtualHere.' });
            }
            res.json({ message: 'VirtualHere ha sido detenido.' });
        });
    } else {
        res.status(400).json({ message: 'Acción no válida.' });
    }
});

// Endpoint para obtener el nombre del dispositivo desde el archivo de configuración
app.get('/get-device-name', (req, res) => {
    try {
        const config = JSON.parse(fs.readFileSync(configFilePath, 'utf-8'));
        res.status(200).json({ deviceName: config.deviceName });
    } catch (error) {
        console.error('Error obteniendo el nombre del dispositivo:', error);
        res.status(500).send('Error obteniendo el nombre del dispositivo');
    }
});
// Endpoint para obtener el pin de la sim desde el archivo de configuración
app.get('/get-sim-pin', (req, res) => {
    try {
        const config = JSON.parse(fs.readFileSync(configFilePath, 'utf-8'));
        res.status(200).json({ simPin: config.simConfig.pin });
    } catch (error) {
        console.error('Error obteniendo el pin de la sim:', error);
        res.status(500).send('Error obteniendo el pin de la sim');
    }
});

// Endpoint para actualizar el nombre del dispositivo en el archivo de configuración
app.get('/set-sim-pin', express.json(), (req, res) => {
    const { newPin } = req.body;
    if (!newPin || typeof newPin !== 'string') {
        return res.status(400).send('Pin invalido');
    }

    try {
        const config = JSON.parse(fs.readFileSync(configFilePath, 'utf-8'));
        config.simConfig.simPin = newPin;

        // Guardar el nuevo nombre en el archivo de configuración
        fs.writeFileSync(configFilePath, JSON.stringify(config, null, 2));
        res.status(200).send('Pin actualizado correctamente');
    } catch (error) {
        console.error('Error actualizando Pin:', error);
        res.status(500).send('Error actualizando Pin');
    }
});

// Endpoint para obtener el pin de la sim desde el archivo de configuración
app.get('/get-network', (req, res) => {
    try {
        const config = JSON.parse(fs.readFileSync(configFilePath, 'utf-8'));
        res.status(200).json({ networkConfig: config.networkConfig });
    } catch (error) {
        console.error('Error obteniendo los ajustes de red:', error);
        res.status(500).send('Error obteniendo los ajustes de red');
    }
});

// Endpoint para actualizar la configuración de red del dispositivo en el archivo de configuración
app.get('/set-network', express.json(), (req, res) => {

    const { ipAddress, gateway, dns, interfaces } = req.body;

    try {
        const config = JSON.parse(fs.readFileSync(configFilePath, 'utf-8'));
        config.networkConfig.ipAddress = ipAddress;
        config.networkConfig.gateway = gateway;
        config.networkConfig.dns = dns;
        config.networkConfig.interfaces = interfaces;

        // Guardar el nuevo nombre en el archivo de configuración
        fs.writeFileSync(configFilePath, JSON.stringify(config, null, 2));
        res.status(200).send('Pin actualizado correctamente');
    } catch (error) {
        console.error('Error actualizando Pin:', error);
        res.status(500).send('Error actualizando Pin');
    }
});

// Endpoint para actualizar el nombre del dispositivo en el archivo de configuración
app.get('/set-device-name', express.json(), (req, res) => {
    const { newName } = req.body;
    if (!newName || typeof newName !== 'string') {
        return res.status(400).send('Nombre de dispositivo inválido');
    }

    try {
        const config = JSON.parse(fs.readFileSync(configFilePath, 'utf-8'));
        config.deviceName = newName;

        // Guardar el nuevo nombre en el archivo de configuración
        fs.writeFileSync(configFilePath, JSON.stringify(config, null, 2));
        res.status(200).send('Nombre del dispositivo actualizado correctamente');
    } catch (error) {
        console.error('Error actualizando el nombre del dispositivo:', error);
        res.status(500).send('Error actualizando el nombre del dispositivo');
    }
});


app.get('/check-first-run', (req, res) => {
    try {
        // Leer la configuración actual desde el archivo config.json
        const config = JSON.parse(fs.readFileSync(configFilePath, 'utf-8'));

        // Verificar si es la primera ejecución (puede ser una propiedad como 'firstRun' en config.json)
        if (config.systemConfig.firstRun === true) {
            return res.json({ firstRun: true });
        } else {
            return res.json({ firstRun: false });
        }
    } catch (error) {
        console.error('Error al leer la configuración:', error);
        res.status(500).send('Error al verificar primera ejecución');
    }
});

app.get('/update', (req, res) => {
    exec('sudo sh /home/rud1/update-code.sh', (error) => {
        if (error) {
            console.error(`Error al actualizar: ${error.message}`);
            return res.json({ success: false, message: 'Error al actualizar el dispositivo.' });
        }
        res.json({ success: true, message: 'Actualización iniciada.' });
    });
});
app.get('/reboot', (req, res) => {
    exec('sudo reboot', (error) => {
        if (error) {
            console.error(`Error al reiniciar: ${error.message}`);
            return res.json({ success: false, message: 'Error al reiniciar el dispositivo.' });
        }
        res.json({ success: true, message: 'Reinicio iniciado.' });
    });
});

app.get('/sim-status', (req, res) => {
    // Ejecutamos el comando mmcli para obtener información del módem
    exec('mmcli -m 0', (error, stdout, stderr) => {
        if (error) {
            console.error(`Error al ejecutar mmcli: ${error.message}`);
            return res.json({ active: false, error: true, message: 'Error al consultar la SIM' });
        }

        // Parseamos la salida para encontrar el estado de la SIM
        const isActive = stdout.includes('state: connected'); // El módem está conectado
        const isError = stdout.includes('state: failed') || stderr; // Algún error en el módem
        const isMissingSim = stdout.includes('sim-missing');
        if (isError) {
            return res.json({ active: false, error: true, message: `Error en la SIM o módem ${isMissingSim ?? ': Falta tarjeta SIM...', ''}` });
        }

        // Respondemos con el estado de la SIM
        return res.json({
            active: isActive,
            error: isError,
            isMissingSim: isMissingSim,
            message: !isMissingSim ? 'SIM Activa y conectada' : 'SIM no conectada o iniciando',
        });
    });
});

app.get('/system-status', (req, res) => {
    // Información de CPU y memoria
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;
    const cpuUsage = os.loadavg()[0]; // Promedio de carga en 1 minuto
    const uptime = os.uptime(); // Tiempo desde el último reinicio en segundos

    // Obtener temperatura del CPU
    exec('vcgencmd measure_temp', (error, stdout, stderr) => {
        if (error) {
            console.error(`Error al obtener la temperatura del CPU: ${error.message}`);
            return res.status(500).json({ error: true, message: 'Error al obtener la temperatura del CPU' });
        }

        const temp = stdout.match(/temp=([\d.]+)/)[1]; // Extraemos la temperatura

        // Obtener espacio en disco
        exec('df -h /', (diskError, diskStdout, diskStderr) => {
            if (diskError) {
                console.error(`Error al obtener el espacio en disco: ${diskError.message}`);
                return res.status(500).json({ error: true, message: 'Error al obtener el espacio en disco' });
            }

            const diskLines = diskStdout.split('\n');
            const diskInfo = diskLines[1].split(/\s+/); // Segunda línea tiene el uso del disco para la raíz "/"
            const totalDisk = diskInfo[1];
            const usedDisk = diskInfo[2];
            const freeDisk = diskInfo[3];

            // Respondemos con toda la información del sistema
            res.json({
                cpuUsage: cpuUsage.toFixed(2),
                totalMem: (totalMem / 1024 / 1024).toFixed(2) + ' MB',
                usedMem: (usedMem / 1024 / 1024).toFixed(2) + ' MB',
                freeMem: (freeMem / 1024 / 1024).toFixed(2) + ' MB',
                uptime: (uptime / 3600).toFixed(2) + ' horas',
                temp: `${temp} °C`,
                totalDisk,
                usedDisk,
                freeDisk,
            });
        });
    });
});

// Endpoint para guardar la contraseña en el archivo de configuración
app.get('/set-password', async (req, res) => {
    const { password } = req.body;

    if (!password) {
        return res.status(400).send('Password is required');
    }

    try {
        // Cifra la contraseña usando bcrypt
        const hashedPassword = await bcrypt.hash(password, 10);

        // Leer la configuración actual desde el archivo config.json
        const config = JSON.parse(fs.readFileSync(configFilePath, 'utf-8'));

        // Actualizar la contraseña cifrada en la configuración
        config.systemConfig.passwordHash = hashedPassword;
        config.systemConfig.firstRun = false;

        // Guardar la nueva configuración en el archivo config.json
        fs.writeFileSync(configFilePath, JSON.stringify(config, null, 2));

        res.send('Password saved successfully and first run file created');
    } catch (error) {
        console.error('Error saving password:', error);
        res.status(500).send('Error saving password');
    }
});

// Endpoint para verificar la contraseña desde el archivo de configuración
app.get('/verify-password', async (req, res) => {
    const { password } = req.body;

    try {
        // Leer la configuración actual desde el archivo config.json
        const config = JSON.parse(fs.readFileSync(configFilePath, 'utf-8'));

        // Verifica si existe la propiedad 'password' en la configuración
        if (!config.systemConfig.passwordHash) {
            return res.status(500).send('No password found in the configuration file');
        }

        // Compara la contraseña ingresada con la almacenada
        const match = await bcrypt.compare(password, config.systemConfig.passwordHash);

        if (match) {
            res.json({ authenticated: true });
        } else {
            res.status(401).send('Incorrect password');
        }
    } catch (error) {
        console.error('Error reading password from config file:', error);
        res.status(500).send('Error reading password from config file');
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);

    if (!fs.existsSync(configFilePath)) {
        generateConfigFile();
    }

    try {
        const config = JSON.parse(fs.readFileSync(configFilePath, 'utf-8')).networkConfig;
        applyNetplanConfig(config);
        console.error('Netplan Configurado');

        // res.status(200).send('Configuración de Netplan aplicada correctamente.');
    } catch (error) {
        console.error('Error configurando Netplan:', error);
        // res.status(500).send('Error configurando Netplan.');
    }

});
