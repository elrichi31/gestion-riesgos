/*
|--------------------------------------------------------------------------
| Routes file
|--------------------------------------------------------------------------
|
| The routes file is used for defining the HTTP routes.
|
*/

import router from '@adonisjs/core/services/router'
import { middleware } from '../start/kernel.js'

router.get('/', async () => {
  return {
    hello: 'world',
  }
})


// Lazy loading para AuthController
const AuthController = () => import('../app/controllers/auth_controller.js')

// Ruta para generar el código QR del 2FA
router.post('/auth/2fa/generate', [AuthController, 'generate2FASecret'])

router.post('/auth/register', [AuthController, 'register'])

// Ruta para iniciar sesión con verificación 2FA
router.post('/auth/login', [AuthController, 'login'])

router.post('/auth/verify-user', [AuthController, 'verifyUser'])

router.post('/auth/logout', [AuthController, 'logout']).use(middleware.auth())

router.get('/auth/user', [AuthController, 'getUser']).use(middleware.auth())

// Ruta para verificar el estado del 2FA
router.get('/auth/2fa/status', [AuthController, 'check2FAStatus']).use(middleware.auth())
