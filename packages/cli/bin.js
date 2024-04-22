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
import readline from 'readline';

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});
const logger = new Logger();
const program = new Command();

const getAuthoAbsolutePath = (path) => {
  if (Path.isAbsolute(path)) {
    return Path.join(path, '.autho');
  }

  return Path.join(process.cwd(), path, '.autho');
};

const toAbsolutePath = (inputPath) => {
  if (Path.isAbsolute(inputPath)) {
    return inputPath;
  } else {
    return Path.join(process.cwd(), inputPath);
  }
};

const basename = (filePath) => {
  const normalizedPath = Path.normalize(filePath);
  const folderName = Path.basename(normalizedPath);

  return folderName;
};

function printLine(text, cursorTo = 0, moveCursor = 0) {
  readline.cursorTo(process.stdout, cursorTo);
  process.stdout.write(text + ' ');
  readline.moveCursor(process.stdout, cursorTo, moveCursor);
}

const countDown = async (textStart, textEnd, seconds) => {
  return new Promise((resolve) => {
    const interval = setInterval(() => {
      printLine(textStart + seconds + 's')
      seconds--;
      if (seconds < 0) {
        printLine(textEnd);
        clearInterval(interval);
        resolve()
      }
    }, 1000);
  })
};

program
  .name('autho')
  .description('Secrets manager')
  .version('0.0.10')
  .option('-p, --password <password>', 'Master password')
  .option('-ph, --passwordHash <passwordHash>', 'Master password hash')
  .option('-n, --name <name>', 'Collection name')
  .option(
    '-data, --dataFolder <folderPath>',
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
      logger.debug(`Reading data from:`, app.db.path());

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
                  await countDown('Expired at: ', 'The code is not longer valid, please generate new code.', 30);
                  process.exit(0);
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

program
  .command('file')
  .description('Encrypt/Decrypt file')
  .option('-f, --filePath <filePath>', 'File path')
  .option('-en, --encrypt', 'Encrypt file', false)
  .option('-de, --decrypt', 'Decrypt file', false)
  .option('--override', 'Override original file', false)
  .action(async (args) => {
    logger.debug(`file:`, args);
    const { encrypt, decrypt, override } = args;
    let { filePath } = args;
    filePath = toAbsolutePath(filePath);
    const encryptionKey = await App.masterKey();
    if (!encrypt && !decrypt) {
      console.log('Please provide either --encrypt or --decrypt');
      process.exit(1);
    } else if (encrypt) {
      if (filePath.endsWith('.autho')) {
        console.log('.autho files are already encrypted.');
        process.exit(1);
      }
      console.log('Encrypting file:', filePath);
      const outputFilePath = override ? filePath : filePath + '.autho';
      Cipher.encryptFile(filePath, outputFilePath, encryptionKey);
    } else if (decrypt) {
      console.log('Decrypting file:', filePath);
      const outputFilePath = filePath.endsWith('.autho')
        ? filePath.replace(/\.autho$/, '')
        : filePath;
      Cipher.decryptFile(filePath, outputFilePath, encryptionKey);
    }
    process.exit(0);
  });

program
  .command('files')
  .description('Encrypt/Decrypt file')
  .option('--input <inputPath>', 'Folder path')
  .option('--output <outputPath>', 'Folder path', process.cwd())
  .option('-en, --encrypt', 'Encrypt folder', false)
  .option('-de, --decrypt', 'Decrypt folder', false)
  .action(async (args) => {
    try {
      logger.debug(`files:`, args);

      const { encrypt, decrypt } = args;
      let { input, output } = args;
      input = toAbsolutePath(input);
      output = toAbsolutePath(output);

      const folderName = basename(input);
      const encryptionKey = await App.masterKey();

      if (!encrypt && !decrypt) {
        console.log('Please provide either --encrypt or --decrypt');
        process.exit(1);
      } else if (encrypt) {
        console.log('Encrypting files:', input);
        const outputFilePath = Path.join(output, folderName + '.gzip.autho');
        await Cipher.encryptFolder({
          inputFolderPath: input, outputFilePath, encryptionKey
        });
        console.log('Created:', outputFilePath);
      } else if (decrypt) {
        console.log('Decrypting files:', input);
        await Cipher.decryptFolder({
          inputFilePath: input, outputFolderPath: output, encryptionKey
        });
      }
    } catch (error) {
      logger.error('Something went wrong, Error: ', error.message);
      console.log(error.stack);
      process.exit(1);
    }

    process.exit(0);
  });

program.parse();
