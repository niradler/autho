import dotenv from 'dotenv';
dotenv.config();

export default {
  masterPasswordHash: process.env.AUTHO_MASTER_PASSWORD_HASH,
  masterPassword: process.env.AUTHO_MASTER_PASSWORD,
  logLevel: process.env.AUTHO_LOG_LEVEL || 'info',
  randomSize: process.env.AUTHO_RANDOM_SIZE || 16,
  encryptionALgo: process.env.AUTHO_ENCRYPTION_ALGO || 'aes-256-gcm',
  hashAlgo: process.env.AUTHO_HASH_ALGO || 'sha256',
  dataFolder: process.env.AUTHO_DATA_FOLDER,
};
