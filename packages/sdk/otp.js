import crypto from 'crypto'

function base32Decode(base32) {
  const base32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  let value = 0;
  let output = new Uint8Array(base32.length * 5 / 8);

  for (let i = 0; i < base32.length; i++) {
    const index = base32chars.indexOf(base32[i].toUpperCase());
    if (index === -1) {
      throw new Error('Invalid base32 character.');
    }
    value = (value << 5) | index;
    bits += '11111';

    if (bits.length >= 8) {
      output[(i * 5 / 8) | 0] = (value >> (bits.length - 8)) & 0xff;
      bits = bits.slice(8);
    }
  }

  return output;
}

function generateTOTP(secret, window = 0) {
  const key = base32Decode(secret);
  const epoch = Math.floor(Date.now() / 1000);
  let counter = Math.floor(epoch / 30) + window;
  const time = Buffer.alloc(8);

  for (let i = 7; i >= 0; i--) {
    time[i] = counter & 0xff;
    counter >>= 8;
  }

  const hmac = crypto.createHmac('sha1', key);
  hmac.update(time);
  const hash = hmac.digest();

  const offset = hash[hash.length - 1] & 0xf;
  const binary = ((hash[offset] & 0x7f) << 24) |
                 ((hash[offset + 1] & 0xff) << 16) |
                 ((hash[offset + 2] & 0xff) << 8) |
                 (hash[offset + 3] & 0xff);

  const token = binary % 1000000;
  return token.toString().padStart(6, '0');
}

function verifyTOTP(secret, token, window = 1) {
  for (let errorWindow = -window; errorWindow <= window; errorWindow++) {
    const generatedToken = generateTOTP(secret, errorWindow);
    if (generatedToken === token) {
      return true;
    }
  }
  return false;
}

export default class OTP {
  constructor(secret) {

    this.options = {
      issuer: 'Autho',
      label: secret.name,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: secret.value,
    };

  }

  generate() {
    return generateTOTP(this.options.secret);
  }

  validate(token, window = 1) {
    return verifyTOTP(this.options.secret, token, window);
  }
}
