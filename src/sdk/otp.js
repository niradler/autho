import * as OTPAuth from "otpauth";
import Cipher from "./cipher.js";

export default class OTP {
  constructor(config, secret, password) {
    const cipher = new Cipher(config);
    const options = {
      issuer: "ACME",
      label: secret.name,
      algorithm: "SHA1",
      digits: 6,
      period: 30,
      secret: cipher.decrypt(secret.value, secret.publicKey, password),
    };

    this.totp = new OTPAuth.TOTP(options);
  }

  generate() {
    return this.totp.generate();
  }

  validate(token, window = 1) {
    return this.totp.validate({ token, window });
  }
}
