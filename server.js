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
    origin: function (origin, callback) {
        // Permite cualquier origen (refleja el origen de la petición)
        callback(null, true);
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
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

// Helper para correo de bienvenida
const enviarCorreoBienvenida = (email, nombre, rol) => {
    const mailOptions = {
        from: `"Soporte SISWEB" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: '¡Bienvenido a SISWEB!',
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden;">
                <div style="background-color: #1565C0; padding: 20px; text-align: center;">
                    <h1 style="color: white; margin: 0;">SISWEB</h1>
                </div>
                <div style="padding: 30px; color: #333;">
                    <h2>¡Hola, ${nombre}!</h2>
                    <p>Te damos la más cordial bienvenida a nuestra plataforma SISWEB.</p>
                    <p>Tu cuenta como <strong>${rol}</strong> ha sido creada exitosamente. Ya puedes ingresar al sistema para gestionar tus seminarios.</p>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="${process.env.FRONTEND_URL || 'https://sisweb.online'}/login" 
                           style="background-color: #1565C0; color: white; padding: 12px 25px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">
                           Iniciar Sesión
                        </a>
                    </div>
                </div>
                <div style="background-color: #f5f5f5; padding: 15px; text-align: center; font-size: 12px; color: #888;">
                    &copy; 2026 Proyecto SISWEB - SENA.
                </div>
            </div>
        `
    };
    transporter.sendMail(mailOptions).catch(err => console.error("Error enviando correo de bienvenida:", err));
};

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
                                enviarCorreoBienvenida(email, nombre, rolFiltro);
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
                            enviarCorreoBienvenida(email, nombre, rolFiltro);
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
        const [users] = await db.promise().query('SELECT id_usuario FROM Usuario WHERE email = ?', [email]);
        
        if (users.length === 0) {
            return res.status(404).json({ message: 'Si el correo existe, recibirá instrucciones.' });
        }

        const token = crypto.randomBytes(20).toString('hex');
        const expiracion = new Date(Date.now() + 3600000); // 1 hora
        await db.promise().query(
            'UPDATE Usuario SET reset_token = ?, token_expiracion = ? WHERE email = ?',
            [token, expiracion, email]
        );

        const mailOptions = {
            from: `"Soporte SISWEB" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Recuperación de Contraseña - SISWEB',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden;">
                    <div style="background-color: #1565C0; padding: 20px; text-align: center;">
                        <h1 style="color: white; margin: 0;">SISWEB</h1>
                    </div>
                    <div style="padding: 30px; color: #333;">
                        <h2>Hola,</h2>
                        <p>Hemos recibido una solicitud para restablecer tu contraseña en la plataforma SISWEB.</p>
                        <p>Haz clic en el siguiente botón para crear una nueva contraseña. <strong>Este enlace expira en 1 hora.</strong></p>
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="${process.env.FRONTEND_URL || 'https://sisweb.online'}/restablecer-password?token=${token}" 
                               style="background-color: #1565C0; color: white; padding: 12px 25px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">
                               Restablecer mi contraseña
                            </a>
                        </div>
                        <p style="font-size: 13px; color: #777;">Si el botón no funciona, copia y pega este link en tu navegador:<br>
                        ${process.env.FRONTEND_URL || 'https://sisweb.online'}/restablecer-password?token=${token}</p>
                    </div>
                    <div style="background-color: #f5f5f5; padding: 15px; text-align: center; font-size: 12px; color: #888;">
                        &copy; 2026 Proyecto SISWEB - SENA.
                    </div>
                </div>
            `
        };

        await transporter.sendMail(mailOptions);
        res.json({ message: 'Correo enviado. Revisa tu bandeja de entrada o spam.' });

    } catch (error) {
        console.error("Error mandando el correo:", error);
        res.status(500).json({ message: 'Error interno del servidor.' });
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
    const sql = `
        SELECT 
            s.*,
            (s.cupos_totales - (SELECT COUNT(*) FROM Inscripcion i WHERE i.id_seminario = s.id_seminario AND i.estado = 'Inscrito')) as cupos_disponibles
        FROM Seminario s 
        WHERE s.fecha >= CURDATE()
        ORDER BY s.fecha ASC
    `;
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json({ error: 'Error al consultar los seminarios' });
        res.status(200).json(results);
    });
});

// Inscribir un Participante a un Seminario (POST)
app.post('/api/inscripciones', async (req, res) => {
    const { id_seminario, id_participante, valor, estado } = req.body;

    if (!id_seminario || !id_participante) {
        return res.status(400).json({ error: 'Se requiere el ID del seminario y del participante' });
    }

    try {
        // Validar cupos disponibles
        const [[seminario]] = await db.promise().query(`
            SELECT s.nombre, s.cupos_totales, 
            (SELECT COUNT(*) FROM Inscripcion WHERE id_seminario = ?) as inscritos
            FROM Seminario s WHERE s.id_seminario = ?
        `, [id_seminario, id_seminario]);

        if (!seminario) return res.status(404).json({ error: 'Seminario no encontrado' });
        if (seminario.cupos_totales - seminario.inscritos <= 0) {
            return res.status(400).json({ error: 'No hay cupos disponibles' });
        }

        // Revisar si ya está inscrito
        const [[inscripcionExitente]] = await db.promise().query(
            'SELECT * FROM Inscripcion WHERE id_seminario = ? AND id_participante = ?',
            [id_seminario, id_participante]
        );
        if (inscripcionExitente) return res.status(400).json({ error: 'Ya estás inscrito en este seminario' });

        const fechaActual = new Date().toISOString().split('T')[0];
        await db.promise().query(
            'INSERT INTO Inscripcion (id_seminario, id_participante, fecha, valor, estado) VALUES (?, ?, ?, ?, ?)',
            [id_seminario, id_participante, fechaActual, valor || 0.00, estado || 'Inscrito']
        );

        // Buscar datos del participante para el correo
        const [[user]] = await db.promise().query(`
            SELECT u.email, p.nombre 
            FROM Participante p 
            JOIN Usuario u ON p.id_usuario = u.id_usuario 
            WHERE p.id_participante = ?
        `, [id_participante]);

        if (user && user.email) {
            const mailOptions = {
                from: `"Soporte SISWEB" <${process.env.EMAIL_USER}>`,
                to: user.email,
                subject: 'Confirmación de Inscripción - SISWEB',
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden;">
                        <div style="background-color: #1565C0; padding: 20px; text-align: center;">
                            <h1 style="color: white; margin: 0;">SISWEB</h1>
                        </div>
                        <div style="padding: 30px; color: #333;">
                            <h2>¡Hola, ${user.nombre}!</h2>
                            <p>Tu inscripción ha sido confirmada exitosamente en el sistema.</p>
                            <p>Seminario: <strong>${seminario.nombre}</strong></p>
                            <p>¡Guarda la fecha y prepárate para asistir!</p>
                        </div>
                        <div style="background-color: #f5f5f5; padding: 15px; text-align: center; font-size: 12px; color: #888;">
                            &copy; 2026 Proyecto SISWEB - SENA.
                        </div>
                    </div>
                `
            };
            transporter.sendMail(mailOptions).catch(err => console.error("Error correo inscripción:", err));
        }

        res.status(201).json({ mensaje: 'Inscripción procesada correctamente' });

    } catch (error) {
        console.error("Error en inscripciones:", error);
        res.status(500).json({ error: 'Error interno del servidor al inscribir' });
    }
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