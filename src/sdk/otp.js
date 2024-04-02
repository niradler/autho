import * as OTPAuth from "otpauth";

export default class OTP {
  constructor(secret) {

    const options = {
      issuer: "Autho",
      label: secret.name,
      algorithm: "SHA1",
      digits: 6,
      period: 30,
      secret: secret.value,
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
