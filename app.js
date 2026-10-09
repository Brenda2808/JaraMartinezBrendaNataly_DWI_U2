const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const bodyParser = require('body-parser');

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('views'));



// BASE DE DATOS
const db = new sqlite3.Database('database.db');

db.serialize(() => {

    db.run(`
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT,
            password_inseguro TEXT,
            password_seguro TEXT
        )
    `);

});



// PAGINA REGISTRO
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/views/registro.html');
});



// PAGINA LOGIN
app.get('/login', (req, res) => {
    res.sendFile(__dirname + '/views/login.html');
});





// REGISTRO DE USUARIO
app.post('/registro', async (req, res) => {

    const usuario = req.body.usuario;
    const password = req.body.password;

    // HASH INSEGURO
    const hashInseguro = crypto
        .createHash('sha256')
        .update(password)
        .digest('hex');

    // HASH SEGURO
    const hashSeguro = await bcrypt.hash(password, 10);

    db.run(`
        INSERT INTO usuarios
        (usuario, password_inseguro, password_seguro)
        VALUES (?, ?, ?)
    `,
    [usuario, hashInseguro, hashSeguro],
    (err) => {

        if(err){

            return res.send(`
                <h1>Error al registrar usuario</h1>

                <a href="/">
                    Volver
                </a>
            `);

        }

        res.send(`
            <html>

            <head>

                <title>Registro Exitoso</title>

                <link rel="stylesheet" href="/style.css">

            </head>

            <body>

                <main class="container">

                    <h1>
                        Usuario Registrado Correctamente
                    </h1>

                <h1>
                    <p>${usuario}</p>
                </h1>
                    
                    <a href="/">
                        Volver al Registro
                    </a>

                    <br><br>

                    <a href="/login">
                        Ir al Login
                    </a>

                </main>

            </body>

            </html>
        `);

    });

});





// LOGIN
app.post('/login', (req, res) => {

    const usuario = req.body.usuario;
    const password = req.body.password;

    db.get(`
        SELECT * FROM usuarios
        WHERE usuario = ?
    `,
    [usuario],
    async (err, row) => {

        if(!row){

            return res.send(`
                <html>

                <head>

                    <link rel="stylesheet" href="/style.css">

                </head>

                <body>

                    <main class="container">

                        <h1>
                            Usuario no encontrado
                        </h1>

                        <a href="/login">
                            Volver
                        </a>

                    </main>

                </body>

                </html>
            `);

        }

        const resultado = await bcrypt.compare(
            password,
            row.password_seguro
        );

        if(resultado){

            res.send(`
                <html>

                <head>

                    <title>Login Exitoso</title>

                    <link rel="stylesheet" href="/style.css">

                </head>

                <body>

                    <main class="container">

                        <h1>
                            LOGIN EXITOSO
                        </h1>

                        <h3>Usuario:</h3>
                        <p>${row.usuario}</p>

                        <h3>Hash Inseguro SHA256</h3>
                        <p class="hash">
                            ${row.password_inseguro}
                        </p>

                        <h3>Hash Seguro bcrypt</h3>
                        <p class="hash">
                            ${row.password_seguro}
                        </p>

                        <a href="/">
                            Cerrar sesión
                        </a>

                    </main>

                </body>

                </html>
            `);

        } else {

            res.send(`
                <html>

                <head>

                    <link rel="stylesheet" href="/style.css">

                </head>

                <body>

                    <main class="container">

                        <h1>
                            Contraseña Incorrecta
                        </h1>

                        <a href="/login">
                            Volver
                        </a>

                    </main>

                </body>

                </html>
            `);

        }

    });

});





// MOSTRAR USUARIOS
app.get('/usuarios', (req, res) => {

    db.all(`
        SELECT * FROM usuarios
    `,
    [],
    (err, rows) => {

        let html = `

        <html>

        <head>

            <title>Usuarios</title>

            <link rel="stylesheet" href="/style.css">

        </head>

        <body>

        <main class="container">

            <h1>
                Usuarios Registrados
            </h1>

            <div class="table-wrapper">

            <table>

                <tr>

                    <th>ID</th>
                    <th>Usuario</th>
                    <th>Hash Inseguro</th>
                    <th>Hash Seguro</th>
                    <th>Eliminar</th>

                </tr>
        `;

        rows.forEach(user => {

            html += `

                <tr>

                    <td>${user.id}</td>

                    <td>${user.usuario}</td>

                    <td class="hash">
                        ${user.password_inseguro}
                    </td>

                    <td class="hash">
                        ${user.password_seguro}
                    </td>

                    <td>

                        <a href="/eliminar/${user.id}"
                        onclick="return confirm('¿Eliminar usuario?')">

                            Eliminar

                        </a>

                    </td>

                </tr>
            `;

        });

        html += `

            </table>

            </div>

            <br>

            <a href="/">
                Volver al Registro
            </a>

        </main>

        </body>

        </html>
        `;

        res.send(html);

    });

});





// ELIMINAR USUARIO
app.get('/eliminar/:id', (req, res) => {

    const id = req.params.id;

    db.run(`
        DELETE FROM usuarios
        WHERE id = ?
    `,
    [id],
    (err) => {

        if(err){

            return res.send(`
                <h1>Error al eliminar usuario</h1>
            `);

        }

        res.redirect('/usuarios');

    });

});





// SERVIDOR
app.listen(5000, () => {
    console.log('Servidor iniciado en puerto 5000');
});