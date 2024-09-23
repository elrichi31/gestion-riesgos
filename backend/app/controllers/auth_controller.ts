import User from '../models/user.js'
import speakeasy from 'speakeasy'
import qrcode from 'qrcode'
import Hash from '@adonisjs/core/services/hash'

export default class AuthController {

    // Registro de un nuevo usuario
    public async register({ request, response }: { request: any, response: any }) {
        const { email, password, fullName } = request.only(['email', 'password', 'fullName'])

        // Verificar si el correo ya está registrado
        const existingUser = await User.findBy('email', email)
        if (existingUser) {
            return response.badRequest({ message: 'El correo ya está registrado' })
        }

        const user = new User()
        user.email = email
        user.fullName = fullName
        user.password = password

        // Guardar el nuevo usuario en la base de datos
        await user.save()

        // Generar el secreto para el 2FA
        const secret = speakeasy.generateSecret({
            name: 'gestion-riesgos', // Nombre de la aplicación
            length: 20,
        })

        // Verificar si se generó correctamente el secreto
        if (!secret.otpauth_url) {
            return response.badRequest({ message: 'Error generando el código QR' })
        }

        // Generar la URL del código QR
        const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url)

        // Guardar el secreto en la base de datos del usuario
        user.twoFactorSecret = secret.base32
        await user.save()

        // Retornar el QR code URL para que el usuario pueda configurar el 2FA
        return response.ok({
            message: 'Usuario registrado exitosamente y 2FA configurado',
            qrCodeUrl,  // Enviar la URL del código QR
            secret: secret.base32  // Enviar el secreto por si es necesario
        })
    }

    public async generate2FASecret({ request, response }: { request: any, auth: any, response: any }) {
        const email = request.input('email')
        const password = request.input('password')

        const user = await User.query().where('email', email).firstOrFail()
        const isPasswordValid = await Hash.verify(user.password, password)
        console.log(isPasswordValid)

        if (!isPasswordValid) {
            return response.unauthorized({ message: 'Credenciales incorrectas' })
        }

        const secret = speakeasy.generateSecret({
            name: 'gestion-riesgos', // Nombre de la aplicación
            length: 20,
        })

        if (!secret.otpauth_url) {
            return response.badRequest({ message: 'Error generando el código QR' })
        }
        const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url)

        user.twoFactorSecret = secret.base32
        await user.save()

        return response.json({ qrCodeUrl, secret: secret.base32 })
    }

    public async login({ request, response }: { request: any, auth: any, response: any }) {
        const { email, password, token } = request.only(['email', 'password', 'token'])
        const user = await User.findByOrFail('email', email)

        const isPasswordValid = await Hash.verify(user.password, password)
        if (!isPasswordValid) {
            return response.unauthorized({ message: 'Credenciales incorrectas' })
        }

        if (!user.twoFactorSecret) {
            return response.badRequest({ message: '2FA no configurado' })
        }

        const verified = speakeasy.totp.verify({
            secret: user.twoFactorSecret,
            encoding: 'base32',
            token: token, // Token ingresado por el usuario
        })

        if (verified) {
            const jwtToken = await User.accessTokens.create(user, ['*'], { expiresIn: '4h' })
            return response.ok({ message: 'Login exitoso', token: jwtToken, user: user })
        } else {
            return response.unauthorized({ message: 'Token 2FA inválido' })
        }
    }

    public async verifyUser ({ request, response }: { request: any, response: any }) {
        const { email, password } = request.only(['email', 'password'])

        try {
            const user = await User.findByOrFail('email', email)
            const isPasswordValid = await Hash.verify(user.password, password)
            if (!isPasswordValid) {
                return response.unauthorized({ message: 'Credenciales incorrectas' })
            }
            return response.ok({ message: 'Usuario verificado' })
        } catch (error) {
            return response.notFound({ message: 'Usuario no encontrado' })
        }

    }

    public async check2FAStatus({ auth, response }: { auth: any, response: any }) {
        const user = auth.user

        if (user.twoFactorSecret) {
            return response.json({ message: '2FA configurado' })
        } else {
            return response.json({ message: '2FA no configurado' })
        }
    }

    public async logout({ auth, response }:  { auth: any, response: any }) {
        try {
          // Obtener el token actual
          await auth.use('api').logout
          return response.ok({ message: 'Sesión cerrada correctamente' });
        } catch (error) {
            console.log(error)
          return response.internalServerError({ message: 'Error al cerrar la sesión' });
        }
      }
      

    public async getUser({ auth, response }: { auth: any, response: any }) {
        const user = auth.user
        return response.ok(user)
    }
}
