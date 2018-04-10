var express = require('express');
var app = express();
var bcrypt = require('bcryptjs');
var jwt = require('jsonwebtoken');

var SEED = require('../config/config').SEED;

var Usuario = require('../models/usuario');

const GOOGLE_CLIENT_ID = require('../config/config').GOOGLE_CLIENT_ID;
const GOOGLE_SECRET = require('../config/config').GOOGLE_SECRET;

const { OAuth2Client } = require('google-auth-library');
const client = new OAuth2Client(GOOGLE_CLIENT_ID, GOOGLE_SECRET);

// ==========================================
// Autentificación de Google  								      
// ==========================================       
app.post('/google', (req, res) => {
    var token = req.body.token || 'XXX';
    client.verifyIdToken({
            idToken: token,
            audience: GOOGLE_CLIENT_ID, // Specify the CLIENT_ID of the app that accesses the backend
            // Or, if multiple clients access the backend:
            //[CLIENT_ID_1, CLIENT_ID_2, CLIENT_ID_3]
        },
        (e, login) => {
            if (e) {
                return res.status(400).json({
                    ok: false,
                    mensaje: 'Token no válido',
                    errors: e
                });
            }
            const payload = login.getPayload();
            const userid = payload['sub'];
            // If request specified a G Suite domain:
            //const domain = payload['hd'];

            Usuario.findOne({ email: payload.email }, (err, usuario) => {
                if (err) {
                    return res.status(500).json({
                        ok: true,
                        mensaje: 'Error al buscar usuario - login',
                        errors: err
                    });
                }

                if (usuario) {
                    if (usuario.google === false) {
                        return res.status(400).json({
                            ok: true,
                            mensaje: 'Debe de usuar su autenticación normal'
                        });
                    } else {
                        usuario.password = ';)';
                        var token = jwt.sign({ usuario: usuario }, SEED, { expiresIn: 14400 }); // 4 Horas

                        res.status(200).json({
                            ok: true,
                            usuario: usuario,
                            token: token,
                            id: usuario._id
                        });
                    }
                    // Si el usuario no existe por correo
                } else {
                    var usuario = new Usuario();
                    usuario.nombre = payload.name;
                    usuario.email = payload.email;
                    usuario.password = ';)';
                    usuario.img = payload.picture;
                    usuario.google = true;
                    usuario.save((err, usuarioBD) => {
                        if (err) {
                            return res.status(500).json({
                                ok: true,
                                mensaje: 'Error al crear usuario - google',
                                errors: err
                            });
                        }

                        var token = jwt.sign({ usuario: usuarioBD }, SEED, { expiresIn: 14400 }); // 4 Horas

                        res.status(200).json({
                            ok: true,
                            usuario: usuarioBD,
                            token: token,
                            id: usuarioBD._id
                        });

                    })
                }
            });

        });
});

// ==========================================
// Autemtificacion normal  								      
// ==========================================
app.post('/', (req, res) => {
    var body = req.body;
    Usuario.findOne({ email: body.email }, (err, usuarioDB) => {
        if (err) {
            return res.status(500).json({
                ok: false,
                mensaje: 'Error al buscar usuario',
                errors: err
            });
        }
        if (!usuarioDB) {
            return res.status(400).json({
                ok: false,
                mensaje: 'Credenciales incorrectas - email',
                errors: err
            });
        }
        if (!bcrypt.compareSync(body.password, usuarioDB.password)) {
            return res.status(400).json({
                ok: false,
                mensaje: 'Credenciales incorrectas - password',
                errors: err
            });
        }

        // Crear un token!!!
        usuarioDB.password = ';)';
        var token = jwt.sign({ usuario: usuarioDB }, SEED, { expiresIn: 14400 }); // 4 Horas

        res.status(200).json({
            ok: true,
            usuario: usuarioDB,
            token: token,
            id: usuarioDB._id
        });
    })

});


module.exports = app;