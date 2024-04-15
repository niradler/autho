import Cipher from '../../sdk/cipher.js';
import config from '../../shared/config.js';
import logger from '../../shared/logger.js';
import Secrets from '../../sdk/Secrets.js';
import DB from '../../sdk/db.js';

export const authMiddleware = (req, res, next) => {
  try {
    const masterPassword =
      req.headers['x-master-password'] || config.masterPassword;
    let masterPasswordHash =
      req.headers['x-master-password-hash'] || config.masterPasswordHash;

    if (!masterPasswordHash && !masterPassword) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    masterPasswordHash = masterPasswordHash || Cipher.hash(masterPassword);

    const db = new DB({
      encryptionKey: masterPasswordHash,
      dataFolder: config.dataFolder,
      name: config.name,
    });

    req.app = {
      masterPasswordHash,
      db,
      secrets: new Secrets(db),
    };
  } catch (error) {
    logger.error('Error in authMiddleware', error);
    res.status(401);
    next('Invalid master password');
  }

  next();
};
