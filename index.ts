import fastify from 'fastify';
import fastifyProxy from '@fastify/http-proxy';
import fastifyCookie from '@fastify/cookie';
import fastifyForm from '@fastify/formbody';
import fs from 'fs';
import { Static, Type } from '@sinclair/typebox';
import speakeasy from 'speakeasy';
import crypto from 'crypto';
import qrcode from 'qrcode';
import dotenv from 'dotenv';

dotenv.config();

const proxyTo = process.env.PROXY_TO;
if (!proxyTo || typeof proxyTo !== 'string') throw new Error('Invalid proxyTo');

const sessionValidTime = Number(process.env.SESSION_VALID_TIME);
if (isNaN(sessionValidTime) || sessionValidTime < 0) throw new Error('Invalid sessionValidTime');

console.log('Reading config.json');
if (!fs.existsSync('./config.json')) fs.writeFileSync('./config.json', '{}');
const config = JSON.parse(fs.readFileSync('./config.json').toString('utf-8'));

let generatedSecret: string | undefined;
let otpSecret = config.otpSecret;

if (!otpSecret) {
    console.log('Generating TOTP secret now');
    const secret = speakeasy.generateSecret();
    config.otpSecret = otpSecret = secret.base32;
    generatedSecret = secret.otpauth_url;
}

if (typeof otpSecret !== 'string') throw new Error('Invalid otpSecret');

fs.writeFileSync('./config.json', JSON.stringify(config));

interface Session {
    authDate: Date,
    expireDate: Date
}

const app = fastify();
const sessionMap = new Map<string, Session>();
const indexHtml = fs.readFileSync('./index.html').toString('utf-8');
const qrHtml = fs.readFileSync('./qrcode.html').toString('utf-8');

app.register(fastifyCookie);

app.register(fastifyProxy, {
    upstream: proxyTo, preHandler: (req, reply, done) => {
        const authCookie = req.cookies._OTP_AUTH;
        const session = sessionMap.get(authCookie);
        if (authCookie && session) {
            if (session.expireDate.getTime() >= Date.now()) {
                // Session 유효. 그대로 요청 처리
                done();
                // 유효기간 연장
                session.expireDate = new Date(Date.now() + sessionValidTime);
                return;
            } else {
                sessionMap.delete(authCookie);
            }
        }

        // Session 유효하지 않으므로 리다이렉트
        reply.redirect(302, '/_otp_auth');
        done();
    }
});

app.register(async (fastify, done) => {
    fastify.register(fastifyForm);

    fastify.get('/', (req, res) => {
        if (generatedSecret) {
            console.log('Someone read OTP QR Code');
            qrcode.toDataURL(generatedSecret, (err, dataUrl) => {
                if (err) {
                    res.status(400).send({message: 'Error while generating QR Code'});
                    return;
                }
                res.type('text/html').send(qrHtml.replace('{PLACEHOLDER}', `src="${dataUrl}"`));
            });
            generatedSecret = '';
            return;
        }
        res.type('text/html').send(indexHtml);
    });

    const OTPSubmitBody = Type.Object({
        otp: Type.String()
    });

    type OTPSubmitBodyType = Static<typeof OTPSubmitBody>

    fastify.post<{
        Body: OTPSubmitBodyType
    }>('/', {
        schema: {
            body: OTPSubmitBody
        }
    }, (req, res) => {
        if (speakeasy.totp.verify({ secret: otpSecret, encoding: 'base32', token: req.body.otp})) {
            const uuid = crypto.randomUUID();
            const session: Session = {
                authDate: new Date(),
                expireDate: new Date(Date.now() + sessionValidTime)
            }
            sessionMap.set(uuid, session);
            res.setCookie('_OTP_AUTH', uuid, {
                path: '/'
            }).redirect(302, '/');
        } else {
            // 새로고침
            res.redirect(302, '');
        }
    });
}, {
    prefix: '/_otp_auth'
})

// 주기적으로 유효하지 않은 세션 청소
setInterval(() => {
    sessionMap.forEach((value, key) => {
        if (value.expireDate.getTime() < Date.now()) {
            // 이거 다른 언어에서는 ConcurrentModification 머시기 오류 나던데 자바스크립트는 괜찮은가..
            sessionMap.delete(key);
        }
    });
}, 1000 * 1800);

app.listen(3000, (err, address) => {
    if (err) {
        console.error('Failed to start server: ' + err);
        process.exit();
    }
    console.log(`Listening on ${address}`);
});
