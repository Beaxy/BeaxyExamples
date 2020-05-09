const https = require('https');
const http = require('http');
const crypto = require('crypto');
const bigintCryptoUtils = require('bigint-crypto-utils');


const API_KEY = '<API_KEY>';
const PRIVATE_KEY = '<PRIVATE_KEY>';
const HOST = 'https://tradingapi.beaxy.com';

const fetch = async (url, method = 'GET', body = null, headers = {}) => {
    return new Promise((resolve, reject) => {
        const request = (url.startsWith('https:') ? https : http).request(url, {
            method,
            headers: {
                'Content-Type': 'application/json',
                ...headers,
            },
        }, (response) => {

            response.on('data', (buffer) => {
                if (response.statusCode >= 200 && response.statusCode < 400) {
                    resolve(buffer.toString('utf-8'));
                } else {
                    reject(new Error(response.statusCode + buffer.toString('utf-8')));
                }
            });
        });

        if (body) {
            request.write(JSON.stringify(body))
        }

        request.on('error', reject);

        request.end();
    });
};
/**
 * Convert base64 string to BigInt
 * @param {string} base64Str 
 */
const fromBase64 = (base64Str) => BigInt('0x' + Buffer.from(base64Str, 'base64').toString('hex'));

/**
 * Makes Java specific conversion of BigInt to Buffer
 * @param {BigInt} bigInt 
 */
const bigIntToBuffer = (bigInt) => {
    const hex = bigInt.toString(16);
    // For Java BigInts the length of byte[] representation of BigIntegers should be exactly (ceil((number.bitLength() + 1)/8)) so we right-pad the number with 0s
    const str = '0'.repeat(Math.ceil((bigInt.toString(2).length + 1) / 8) * 2 - hex.length) + hex;
    return Buffer.from(str, 'hex');
};

/**
 * Convert BigInt to base64 string
 * @param {BigInt} bigInt 
 */
const toBase64 = (bigInt) => bigIntToBuffer(bigInt).toString('base64');

const main = async () => {

    const singInAttemptResponse = await fetch(`${HOST}/api/v1/login/attempt`, 'POST', {
        api_key_id: API_KEY
    });

    const singInAttempt = JSON.parse(singInAttemptResponse);
    const dhModulus = fromBase64(singInAttempt.dh_modulus);
    const dhBase = fromBase64(singInAttempt.dh_base);

    const privateKey = crypto.createPrivateKey({
        key: `-----BEGIN PRIVATE KEY-----\n${PRIVATE_KEY}\n-----END PRIVATE KEY-----`,
        format: 'pem',
        type: 'pkcs8'
    });

    const signer = crypto.createSign('RSA-SHA256');
    signer.write(Buffer.from(singInAttempt.challenge, 'base64'));
    const signature = signer.sign(privateKey, 'base64');
    const buffer = crypto.randomBytes(512);
    const dhNumber = BigInt('0x' + buffer.toString('hex'));
    const dhKey = bigintCryptoUtils.modPow(dhBase, dhNumber, dhModulus);

    const signInResponse = await fetch(`${HOST}/api/v1/login/confirm`, 'POST', {
        session_id: singInAttempt.session_id,
        signature,
        dh_key: toBase64(dhKey),
    });

    const signIn = JSON.parse(signInResponse);

    const signKey = bigintCryptoUtils.modPow(fromBase64(signIn.dh_key), dhNumber, dhModulus);
    const secretKey = crypto.createSecretKey(bigIntToBuffer(signKey));

    const nonce = Date.now();
    const payload = `GET/api/v1/accountsX-Deltix-Nonce=${nonce}&X-Deltix-Session-Id=${singInAttempt.session_id}`;
    const requestSignature = crypto.createHmac('SHA384', secretKey).update(payload).digest('base64');

    const accountsResponse = await fetch(`${HOST}/api/v1/accounts`, 'GET', void 0, {
        'X-Deltix-Nonce': nonce,
        'X-Deltix-Session-Id': singInAttempt.session_id,
        'X-Deltix-Signature': requestSignature,
    });

    const accounts = JSON.parse(accountsResponse);

    console.log(accounts.map(account => account.currency_id).join(', '));
};

return main();