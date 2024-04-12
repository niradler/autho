#!/usr/bin/env node

import { Command } from 'commander';
import Path from 'path';
import { prompt } from './utils.js';
import App from './app.js';
import Cipher from 'sdk/cipher.js';
import createSecret from './wizards/createSecret.js';
import getEncryptionKey from './wizards/getEncryptionKey.js';
import getSecret from './wizards/getSecret.js';
import OTP from 'sdk/otp.js';
import { Logger } from 'shared/logger.js';

const logger = new Logger();
const program = new Command();

const getAuthoAbsolutePath = (path) => {
  if (Path.isAbsolute(path)) {
    return Path.join(path, '.autho');
  }

  return Path.join(process.cwd(), path, '.autho');
};

program
  .name('autho')
  .description('Secrets manager')
  .version('0.0.1')
  .option('-p, --password <password>', 'Master password')
  .option('-ph, --passwordHash <passwordHash>', 'Master password hash')
  .option('-n, --name <name>', 'Collection name', 'default')
  .option(
    '-d, --dataFolder <folderPath>',
    'Folder path to store secrets db',
    getAuthoAbsolutePath
  )
  .action(async (args) => {
    try {
      logger.debug('args:', args);
      args.encryptionKey = await App.masterKey(
        args.password,
        args.passwordHash
      );
      const app = new App(args);
      logger.info(`Reading data from:`, app.db.path());

      let choices = [
        { value: 'create', name: 'Create new secret' },
        { value: 'read', name: 'Read secret' },
        { value: 'delete', name: 'Delete secret' },
      ];

      const { action } = await prompt({
        name: 'action',
        type: 'list',
        choices,
        required: true,
      });

      switch (action) {
        case 'create':
          await createSecret(app);
          break;

        case 'read':
          {
            const readSecret = await getSecret(app);
            let encryptionKey = app.db.encryptionKey;
            if (readSecret.protected) {
              encryptionKey = await getEncryptionKey();
            }

            readSecret.value = Cipher.decrypt({ ...readSecret, encryptionKey });

            switch (readSecret.type) {
              case 'password':
                console.log('Username:', readSecret.typeOptions.username);
                console.log('Password:', readSecret.value);
                break;
              case 'note':
                console.log('Note:', readSecret.value);
                break;
              case 'otp':
                {
                  const otp = new OTP(readSecret);
                  console.log('OTP code:', otp.generate());
                  setTimeout(() => {
                    console.log('Expired');
                    process.exit(0);
                  }, 30000);
                }

                break;
            }
          }

          break;
        case 'delete':
          {
            const deleteSecret = await getSecret(app);
            await app.secrets.remove(deleteSecret.id);
            console.log('Removed');
            process.exit(0);
          }
          break;
        default:
          console.log('Unknown action:', action);
          process.exit(1);
      }
    } catch (error) {
      logger.error('Something went wrong, Error: ', error.message);
      console.log(error.stack);
      process.exit(1);
    }
  });

program.parse();
