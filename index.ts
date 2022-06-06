import dotenv from 'dotenv';
import fastify from 'fastify';
import fastifyProxy from '@fastify/http-proxy';
import fastifyCookie from '@fastify/cookie';
import fastifyForm from '@fastify/formbody';
import fs from 'fs';
import { Static, Type } from '@sinclair/typebox';
import totp from 'totp-generator';
import crypto from 'crypto';

dotenv.config();

const proxyTo = process.env.PROXY_TO;
if (!proxyTo) throw new Error('Invalid proxyTo');

const sessionValidTime = Number(process.env.SESSION_VALID_TIME);
if (isNaN(sessionValidTime) || sessionValidTime < 0) throw new Error('Invalid sessionValidTime');

interface Session {
    authDate: Date,
    expireDate: Date
}

const app = fastify();
const sessionMap = new Map<string, Session>();
const otpSecret = 'AAAAAAAAAAAAAAAA';
const indexHtml = fs.readFileSync('./index.html').toString('utf-8');

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
        if (req.body.otp === totp(otpSecret)) {
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
