// =========================================================================
// ARCHIVO: server.js
// DESCRIPCIÓN: API REST para el sistema SISWEB (Registro, Autenticación y Módulos)
// =========================================================================
require('dotenv').config();
// 1. Importación de módulos
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

// 2. Inicialización
const app = express();
const PORT = process.env.PORT || 3000;

// 3. Middlewares
app.use(cors({
    origin: process.env.FRONTEND_URL || '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
}));
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
// CONFIGURACIÓN DE CORREOS (NODEMAILER)
// =========================================================================
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER, // Su Gmail
    pass: process.env.EMAIL_PASS  // La clave de 16 letras
  }
});

// Prueba rápida para ver si el cartero tiene la llave correcta
transporter.verify((error, success) => {
  if (error) {
    console.log("❌ Error con el cartero de Gmail:", error);
  } else {
    console.log("✅ El cartero de Gmail está listo para repartir!");
  }
});

// =========================================================================
// RUTAS (ENDPOINTS) - AUTENTICACIÓN Y USUARIOS
// =========================================================================

// Ruta de Registro con Transacción y bcryptjs
app.post('/api/registro', async (req, res) => {
    const { email, password, rol, nombre, documento, telefono } = req.body;
    if (!email || !password || !nombre) return res.status(400).json({ error: 'Nombre, email y password son obligatorios' });

    let rolFiltro = rol || 'participante';

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        db.getConnection((err, connection) => {
            if (err) return res.status(500).json({ error: 'Error al conectar con la base de datos' });

            connection.beginTransaction((err) => {
                if (err) {
                    connection.release();
                    return res.status(500).json({ error: 'Error iniciando transacción' });
                }

                // Paso 1: Inserta en Usuario
                const sqlUser = 'INSERT INTO Usuario (nombre, documento, email, telefono, password, rol) VALUES (?, ?, ?, ?, ?, ?)';
                connection.query(sqlUser, [nombre || null, documento || null, email, telefono || null, hashedPassword, rolFiltro], (err, userResult) => {
                    if (err) {
                        return connection.rollback(() => {
                            connection.release();
                            if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Correo ya registrado' });
                            return res.status(500).json({ error: 'Error al crear usuario primario' });
                        });
                    }

                    const idUsuario = userResult.insertId;

                    // Paso 2: Inserta en la subtabla correspondiente
                    let sqlSubTable = '';
                    let subParams = [];

                    if (rolFiltro === 'participante') {
                        sqlSubTable = 'INSERT INTO Participante (nombre, correo, matricula, id_usuario) VALUES (?, ?, ?, ?)';
                        subParams = [nombre || null, email, documento || null, idUsuario];
                    } else if (rolFiltro === 'coordinador') {
                        sqlSubTable = 'INSERT INTO Coordinador (nombre, correo, id_usuario) VALUES (?, ?, ?)';
                        subParams = [nombre || null, email, idUsuario];
                    } else if (rolFiltro === 'administrador') {
                        sqlSubTable = 'INSERT INTO Administrador (nombre, id_usuario) VALUES (?, ?)';
                        subParams = [nombre || null, idUsuario];
                    }

                    if (sqlSubTable) {
                        connection.query(sqlSubTable, subParams, (err, subResult) => {
                            if (err) {
                                return connection.rollback(() => {
                                    connection.release();
                                    return res.status(500).json({ error: 'Error al registrar rol específico' });
                                });
                            }

                            connection.commit((err) => {
                                if (err) {
                                    return connection.rollback(() => {
                                        connection.release();
                                        return res.status(500).json({ error: 'Error al confirmar la transacción' });
                                    });
                                }
                                connection.release();
                                res.status(201).json({ mensaje: 'Usuario registrado exitosamente' });
                            });
                        });
                    } else {
                        connection.commit((err) => {
                            if (err) {
                                return connection.rollback(() => {
                                    connection.release();
                                    return res.status(500).json({ error: 'Error al confirmar transacción base' });
                                });
                            }
                            connection.release();
                            res.status(201).json({ mensaje: 'Usuario registrado exitosamente (Sin sub-tabla)' });
                        });
                    }
                });
            });
        });
    } catch (error) {
        res.status(500).json({ error: 'Error al encriptar contraseña' });
    }
});

// Ruta de Login
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    const sql = 'SELECT * FROM Usuario WHERE email = ?';

    db.query(sql, [email], async (err, results) => {
        if (err) return res.status(500).json({ mensaje: 'Error interno' });

        if (results.length > 0) {
            const usuario = results[0];
            // Comparamos el hash de la BD con el password que escribió el usuario
            const match = await bcrypt.compare(password, usuario.password);
            
            if (match) {
                // Remover el campo de la contraseña antes de mandarlo al frontend por seguridad
                delete usuario.password;
                res.status(200).json({ mensaje: 'autenticación satisfactoria', usuario });
            } else {
                res.status(401).json({ mensaje: 'error en la autenticación' });
            }
        } else {
            res.status(401).json({ mensaje: 'error en la autenticación' });
        }
    });
});

// =========================================================================
// RUTAS (ENDPOINTS) - RECUPERACIÓN DE CONTRASEÑA
// =========================================================================

// Solicitar Restablecimiento de Contraseña
app.post('/api/olvide-password', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'El correo es obligatorio' });

    try {
        const [users] = await db.promise().query('SELECT id_usuario, nombre FROM Usuario WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(404).json({ error: 'No existe una cuenta con ese correo' });
        }

        const user = users[0];
        const token = crypto.randomBytes(32).toString('hex');
        
        // El token expira en 1 hora
        const expiration = new Date();
        expiration.setHours(expiration.getHours() + 1);

        await db.promise().query(
            'UPDATE Usuario SET reset_token = ?, token_expiracion = ? WHERE id_usuario = ?',
            [token, expiration, user.id_usuario]
        );

        const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:5173'}/restablecer-password?token=${token}`;

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Recuperación de Contraseña - SISWEB',
            html: `
                <h3>Hola, ${user.nombre || 'Usuario'}</h3>
                <p>Recibimos una solicitud para restablecer tu contraseña.</p>
                <p>Haz clic en el siguiente enlace para crear una nueva contraseña:</p>
                <a href="${resetUrl}" style="display:inline-block; background-color: #007bff; padding: 10px 15px; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0;">Restablecer Contraseña</a>
                <p>Este enlace expirará en 1 hora.</p>
                <p>Si no solicitaste este cambio, ignora este correo.</p>
            `
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error("Error enviando email:", error);
                return res.status(500).json({ error: 'Error al enviar el correo de recuperación' });
            }
            res.json({ message: 'Se ha enviado un correo con las instrucciones a tu bandeja de entrada.' });
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});

// Procesar Nueva Contraseña
app.post('/api/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) return res.status(400).json({ message: 'Datos incompletos.' });

    try {
        const [users] = await db.promise().query(
            'SELECT id_usuario FROM Usuario WHERE reset_token = ? AND token_expiracion > NOW()', 
            [token]
        );

        if (users.length === 0) {
            return res.status(400).json({ message: 'El link es inválido o ya expiró.' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await db.promise().query(
            'UPDATE Usuario SET password = ?, reset_token = NULL, token_expiracion = NULL WHERE id_usuario = ?',
            [hashedPassword, users[0].id_usuario]
        );

        res.json({ message: '¡Contraseña actualizada con éxito! Ya puedes iniciar sesión.' });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error interno al cambiar la clave.' });
    }
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
            console.error('Error in /api/seminarios:', err);
            if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'El código del seminario ya existe' });
            if (err.code === 'ER_NO_REFERENCED_ROW_2') return res.status(400).json({ error: 'El ID del coordinador indicado no existe' });
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
// Obtener todos los Coordinadores (GET)
app.get('/api/coordinadores', (req, res) => {
    db.query('SELECT * FROM Coordinador', (err, results) => {
        if (err) return res.status(500).json({ error: 'Error al consultar coordinadores' });
        res.status(200).json(results);
    });
});

// Obtener todos los Ponentes (GET)
app.get('/api/ponentes', (req, res) => {
    db.query('SELECT * FROM Ponente', (err, results) => {
        if (err) return res.status(500).json({ error: 'Error al consultar ponentes' });
        res.status(200).json(results);
    });
});

// Obtener todos los Recursos (GET)
app.get('/api/recursos', (req, res) => {
    db.query('SELECT * FROM Recurso', (err, results) => {
        if (err) return res.status(500).json({ error: 'Error al consultar recursos' });
        res.status(200).json(results);
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