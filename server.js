// =========================================================================
// ARCHIVO: server.js
// DESCRIPCIÓN: API REST para el sistema SISWEB (Registro y Autenticación)
// =========================================================================

// 1. Importación de módulos
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');

// 2. Inicialización
const app = express();
const PORT = 3000;

// 3. Middlewares
app.use(cors());
app.use(express.json());

// 4. CONEXIÓN A LA NUBE (TiDB) 
const db = mysql.createPool({
    host: 'gateway01.us-east-1.prod.aws.tidbcloud.com', // Pega el host de TiDB
    port: 4000,                                     // El puerto de TiDB
    user: '2dXQdTh6ec48bFA.root',                   // El usuario de TiDB
    password: 'CpnWC8h1LcIFRPEa',                   // La contraseña de TiDB
    database: 'sisweb_db',                          // El nombre de la base de datos
    ssl: {
        rejectUnauthorized: true                    // Obligatorio para la nube
    },
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Verify the pool connection
db.getConnection((err, connection) => {
    if (err) {
        console.error('Error conectando a la base de datos:', err);
        return;
    }
    console.log('Conexión exitosa a la base de datos TiDB en la nube ☁️ (Pool)');
    connection.release();
});

// =========================================================================
// RUTAS (ENDPOINTS)
// =========================================================================

// Ruta de Registro
app.post('/api/registro', (req, res) => {
    const { email, password, rol } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email y password obligatorios' });

    const sql = 'INSERT INTO usuarios (email, password, rol) VALUES (?, ?, ?)';
    db.query(sql, [email, password, rol || 'participante'], (err, result) => {
        if (err) {
            if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Correo ya registrado' });
            return res.status(500).json({ error: 'Error del servidor' });
        }
        res.status(201).json({ mensaje: 'Usuario registrado exitosamente' });
    });
});

// Ruta de Login (Requisito SENA)
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    const sql = 'SELECT * FROM usuarios WHERE email = ? AND password = ?';

    db.query(sql, [email, password], (err, results) => {
        if (err) return res.status(500).json({ mensaje: 'Error interno' });

        if (results.length > 0) {
            res.status(200).json({ mensaje: 'autenticación satisfactoria', usuario: results[0] });
        } else {
            res.status(401).json({ mensaje: 'error en la autenticación' });
        }
    });
});

// 5. Iniciar Servidor
app.listen(PORT, () => {
    console.log(`Servidor API corriendo en http://localhost:${PORT}`);
});