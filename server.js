// =========================================================================
// ARCHIVO: server.js
// DESCRIPCIÓN: API REST para el sistema SISWEB (Registro, Autenticación y Módulos)
// =========================================================================
require('dotenv').config();
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
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: { rejectUnauthorized: true },
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Verificar la conexión al pool
db.getConnection((err, connection) => {
    if (err) {
        console.error('Error conectando a la base de datos:', err);
        return;
    }
    console.log('Conexión exitosa a la base de datos TiDB en la nube ☁️ (Pool)');
    connection.release();
});

// =========================================================================
// RUTAS (ENDPOINTS) - AUTENTICACIÓN Y USUARIOS
// =========================================================================

// Ruta de Registro
app.post('/api/registro', (req, res) => {
    const { email, password, rol } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email y password obligatorios' });

    const sql = 'INSERT INTO Usuario (email, password, rol) VALUES (?, ?, ?)';
    db.query(sql, [email, password, rol || 'participante'], (err, result) => {
        if (err) {
            if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Correo ya registrado' });
            return res.status(500).json({ error: 'Error del servidor' });
        }
        res.status(201).json({ mensaje: 'Usuario registrado exitosamente' });
    });
});

// Ruta de Login
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    const sql = 'SELECT * FROM Usuario WHERE email = ? AND password = ?';

    db.query(sql, [email, password], (err, results) => {
        if (err) return res.status(500).json({ mensaje: 'Error interno' });

        if (results.length > 0) {
            res.status(200).json({ mensaje: 'autenticación satisfactoria', usuario: results[0] });
        } else {
            res.status(401).json({ mensaje: 'error en la autenticación' });
        }
    });
});

// Obtener Todos los Usuarios
app.get('/api/usuarios', (req, res) => {
    const sql = 'SELECT id_usuario, nombre, email, rol FROM Usuario';

    db.query(sql, (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Error al obtener la lista de usuarios' });
        }
        res.status(200).json(results);
    });
});

// =========================================================================
// RUTAS (ENDPOINTS) - MÓDULO DE SEMINARIOS E INSCRIPCIONES
// =========================================================================

// Crear un nuevo Seminario (POST)
app.post('/api/seminarios', (req, res) => {
    const { codigo, nombre, descripcion, fecha, id_coordinador } = req.body;

    if (!codigo || !nombre || !fecha || !id_coordinador) {
        return res.status(400).json({ error: 'Faltan datos obligatorios para crear el seminario' });
    }

    const sql = 'INSERT INTO Seminario (codigo, nombre, descripcion, fecha, id_coordinador) VALUES (?, ?, ?, ?, ?)';
    db.query(sql, [codigo, nombre, descripcion, fecha, id_coordinador], (err, result) => {
        if (err) {
            if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'El código del seminario ya existe' });
            return res.status(500).json({ error: 'Error al crear el seminario en la BD' });
        }
        res.status(201).json({ mensaje: 'Seminario creado exitosamente', id: result.insertId });
    });
});

// Obtener todos los Seminarios (GET)
app.get('/api/seminarios', (req, res) => {
    const sql = 'SELECT * FROM Seminario ORDER BY fecha ASC';
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json({ error: 'Error al consultar los seminarios' });
        res.status(200).json(results);
    });
});

// Inscribir un Participante a un Seminario (POST)
app.post('/api/inscripciones', (req, res) => {
    const { id_seminario, id_participante, valor, estado } = req.body;

    if (!id_seminario || !id_participante) {
        return res.status(400).json({ error: 'Se requiere el ID del seminario y del participante' });
    }

    const fechaActual = new Date().toISOString().split('T')[0];
    const sql = 'INSERT INTO Inscripcion (id_seminario, id_participante, fecha, valor, estado) VALUES (?, ?, ?, ?, ?)';

    db.query(sql, [id_seminario, id_participante, fechaActual, valor || 0.00, estado || 'Inscrito'], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Error al registrar la inscripción' });
        }
        res.status(201).json({ mensaje: 'Inscripción procesada correctamente' });
    });
});

// =========================================================================
// MÓDULO DE CONSULTAS DE INSCRIPCIONES
// =========================================================================

// Ver mis seminarios inscritos (Para el Participante)
app.get('/api/mis-inscripciones/:id_participante', (req, res) => {
    const { id_participante } = req.params;

    // Hacemos un JOIN para traer los datos del seminario y el estado de la inscripción
    const sql = `
        SELECT s.codigo, s.nombre, s.fecha, i.estado, i.fecha as fecha_inscripcion 
        FROM Inscripcion i 
        JOIN Seminario s ON i.id_seminario = s.id_seminario 
        WHERE i.id_participante = ?
        ORDER BY s.fecha ASC
    `;

    db.query(sql, [id_participante], (err, results) => {
        if (err) return res.status(500).json({ error: 'Error al consultar tus inscripciones' });
        res.status(200).json(results);
    });
});

// Ver estudiantes inscritos en un seminario (Para el Coordinador)
app.get('/api/seminario-inscritos/:id_seminario', (req, res) => {
    const { id_seminario } = req.params;

    // Hacemos un JOIN para traer los datos del participante
    const sql = `
        SELECT p.nombre, p.correo, p.matricula, i.estado, i.fecha as fecha_inscripcion 
        FROM Inscripcion i 
        JOIN Participante p ON i.id_participante = p.id_participante 
        WHERE i.id_seminario = ?
    `;

    db.query(sql, [id_seminario], (err, results) => {
        if (err) return res.status(500).json({ error: 'Error al consultar los estudiantes del seminario' });
        res.status(200).json(results);
    });
});

// =========================================================================
// 5. Iniciar Servidor
// =========================================================================
app.listen(PORT, () => {
    console.log(`Servidor API corriendo en http://localhost:${PORT}`);
});