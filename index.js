// server.js
const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt'); // Importar bcrypt
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
const wgConfigPath = '/etc/wireguard/wg0.conf'; // Archivo de configuración de WireGuard
const logFilePath = '/var/log/syslog';

let lastLogPosition = 0; // Variable para rastrear la última posición leída
let sentLogs = []; // Para almacenar las entradas de log que ya se han enviado

// Función para leer los datos existentes de WireGuard del archivo wg0.conf
function extractKeysFromWgConfig() {
    const wgConfigContent = fs.readFileSync(wgConfigPath, 'utf-8');

    const privateKey = wgConfigContent.match(/PrivateKey = (.+)/)[1];
    const publicKey = wgConfigContent.match(/PublicKey = (.+)/)[1];
    const presharedKey = wgConfigContent.match(/PresharedKey = (.+)/)[1];

    return { privateKey, publicKey, presharedKey };
}

async function generateConfigFile() {
    try {
        // Generar claves públicas y privadas
        const { privateKey, publicKey, presharedKey } = extractKeysFromWgConfig();

        const response = await fetch('https://api.ipify.org?format=json');
        const { ip: publicIp } = await response.json();

        // Plantilla de configuración
        const configTemplate = {
            deviceName: "RaspberryPi-001",
            vpnConfig: {
                privateKey: privateKey,
                publicKey: publicKey,
                presharedKey: presharedKey,
                endpoint: `${publicIp}:51820`,
                allowedIPs: "0.0.0.0/0, ::/0",
                dns: "1.1.1.1",
                persistentKeepalive: 25
            },
            systemConfig: {
                firstRun: true,
                passwordHash: "",
                wireGuardConfigPath: wgConfigPath
            }
        };

        // Escribir el archivo de configuración
        fs.writeFileSync(configFilePath, JSON.stringify(configTemplate, null, 2));

        console.log('Archivo de configuración generado correctamente.');
    } catch (error) {
        console.error('Error generando archivo de configuración:', error);
    }
}

function restartWireguard() {
    exec('sudo systemctl restart wg-quick@wg0', (error, stdout, stderr) => {
        if (error) {
            console.error('Error reiniciando WireGuard:', error);
            return res.status(500).send('Error reiniciando WireGuard');
        }
    });
}


// Guardar la IP pública y generar archivo de cliente
async function generateVpnClient(req, res) {
    try {
        // Obtener IP pública
        const response = await fetch('https://api.ipify.org?format=json');
        const { ip: publicIp } = await response.json();

        // Leer la configuración actual
        const config = JSON.parse(fs.readFileSync(configFilePath, 'utf-8'));

        // Leer las claves y configuración del archivo /root/client.conf
        const clientConfPath = '/root/client.conf';
        const clientConf = fs.readFileSync(clientConfPath, 'utf-8');

        // Parsear las claves necesarias del archivo /root/client.conf
        const privateKeyMatch = clientConf.match(/PrivateKey\s*=\s*(.+)/);
        const publicKeyMatch = clientConf.match(/PublicKey\s*=\s*(.+)/);
        const presharedKeyMatch = clientConf.match(/PresharedKey\s*=\s*(.+)/);

        if (!privateKeyMatch || !publicKeyMatch || !presharedKeyMatch) {
            throw new Error('No se encontraron las claves en /root/client.conf');
        }

        const privateKey = privateKeyMatch[1].trim();
        const publicKey = publicKeyMatch[1].trim();
        const presharedKey = presharedKeyMatch[1].trim();

        // Cambiar la configuración de WireGuard del servidor (no cliente)
        const wgConfig = fs.readFileSync(wgConfigPath, 'utf-8');
        const newWgConfig = wgConfig.replace(/Endpoint = .*/, `Endpoint = ${publicIp}:51820`);
        fs.writeFileSync(wgConfigPath, newWgConfig);

        // Crear archivo de configuración del cliente WireGuard
        const clientConfig = `[Interface]
Address = 10.7.0.2/24
DNS = ${config.vpnConfig.dns}
PrivateKey = ${privateKey}

[Peer]
PublicKey = ${publicKey}
PresharedKey = ${presharedKey}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ${publicIp}:51820
PersistentKeepalive = 25`;

        const clientFileName = `${config.deviceName}.conf`;
        const clientFilePath = path.join(__dirname, clientFileName);
        fs.writeFileSync(clientFilePath, clientConfig);

        // Reiniciar WireGuard para aplicar la nueva configuración del servidor
        restartWireguard();

        // Devolver el archivo de cliente para que el usuario lo descargue
        res.download(clientFilePath, clientFileName, (err) => {
            if (err) throw err;
            fs.unlinkSync(clientFilePath); // Eliminar archivo después de la descarga
        });
    } catch (error) {
        console.error('Error generando cliente VPN:', error);
        res.status(500).send('Error generando cliente VPN');
    }
}

function sendLogs(res, filter = null, noFilter = null) {
    const stats = fs.statSync(logFilePath);

    // Leer el archivo de log completo al inicio
    const logData = fs.readFileSync(logFilePath, 'utf-8');
    const logEntries = logData.split('\n').filter(Boolean); // Divide en líneas y elimina vacías

    // Envía las entradas existentes al inicio
    logEntries.forEach((entry) => {
        if (!sentLogs.includes(entry)) {
            if (noFilter && !entry.includes(noFilter)) return
            if (filter && entry.includes(filter)) return

            res.write(`data: ${entry}\n\n`);
            sentLogs.push(entry); // Añade la entrada a los logs enviados
        }
    });

    lastLogPosition = stats.size; // Actualiza la posición inicial
}

function getLogEntry(res, filter = null, noFilter = null) {
    const stats = fs.statSync(logFilePath);

    if (stats.size > lastLogPosition) {
        const logStream = fs.createReadStream(logFilePath, {
            start: lastLogPosition,
            end: stats.size,
        });

        let logData = '';

        logStream.on('data', (chunk) => {
            logData += chunk;
        });

        logStream.on('end', () => {
            const logEntries = logData.split('\n').filter(Boolean); // Divide en líneas y elimina vacías
            lastLogPosition = stats.size; // Actualiza la posición del último log leído
            logEntries.forEach((entry) => {
                if (!sentLogs.includes(entry)) { // Solo envía si no se ha enviado antes
                    if (noFilter && !entry.includes(noFilter)) return
                    if (filter && entry.includes(filter)) return

                    res.write(`data: ${entry}\n\n`);
                    sentLogs.push(entry); // Añade la entrada a los logs enviados
                }
            });
        });
    }
}

// Ruta para acceder a los logs en tiempo real
app.get('/vpn-logs', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    lastLogPosition = 0;
    sentLogs = []

    sendLogs(res, null, 'wireguard:');
    // Aquí puedes usar setInterval o algún otro mecanismo para comprobar cambios
    const intervalId = setInterval(() => {
        getLogEntry(res, null, 'wireguard:');
    }, 300); // Cambia la frecuencia según tus necesidades

    // Limpia el intervalo al cerrar la conexión
    req.on('close', () => {
        clearInterval(intervalId);
        res.end();
    });
});
// Ruta para acceder a los logs en tiempo real
app.get('/sys-logs', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    lastLogPosition = 0;
    sentLogs = []

    sendLogs(res, 'wireguard:', null);
    // Aquí puedes usar setInterval o algún otro mecanismo para comprobar cambios
    const intervalId = setInterval(() => {
        getLogEntry(res, 'wireguard:', null);
    }, 300); // Cambia la frecuencia según tus necesidades

    // Limpia el intervalo al cerrar la conexión
    req.on('close', () => {
        clearInterval(intervalId);
        res.end();
    });
});

// Endpoint para iniciar/detener VirtualHere
app.post('/virtualhere/:action', (req, res) => {
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

// Descargar archivo de cliente
app.get('/download-vpn-client', generateVpnClient);

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

// Endpoint para actualizar el nombre del dispositivo en el archivo de configuración
app.post('/set-device-name', express.json(), (req, res) => {
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

// Ruta para reiniciar WireGuard después de la configuración
app.post('/restart-wireguard', (req, res) => {
    restartWireguard()
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

app.post('/reboot', (req, res) => {
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

        if (isError) {
            return res.json({ active: false, error: true, message: 'Error en la SIM o módem' });
        }

        // Respondemos con el estado de la SIM
        return res.json({
            active: isActive,
            error: !isActive,
            message: isActive ? 'SIM Activa y conectada' : 'SIM no conectada o iniciando',
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

app.get('/vpn-status', (req, res) => {
    exec('sudo wg show', (error, stdout, stderr) => {
        if (error) {
            console.error(`Error al consultar el estado de la VPN: ${error.message}`);
            return res.json({ success: false, error: error.message, message: 'Error al consultar la VPN.' });
        }
        res.json({
            success: true,
            active: true,
            port: stdout.match(/listening\s*port:\s*(.+)/)[1],
            interface: stdout.match(/interface:\s*(.+)/)[1],
            allowedIPs: stdout.match(/allowed\s*ips:\s*(.+)/)[1]
        });
    });
});

// Endpoint para guardar la contraseña en el archivo de configuración
app.post('/set-password', async (req, res) => {
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
app.post('/verify-password', async (req, res) => {
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
});
