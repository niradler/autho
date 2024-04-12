import { prompt } from '../utils.js';
import getEncryptionKey from './getEncryptionKey.js';

const wizard = async (app) => {
  const secrets = app.secrets;
  const info = await prompt([
    {
      name: 'name',
      message: 'name:',
      type: 'input',
      required: true,
    },
    {
      name: 'type',
      message: 'type:',
      type: 'list',
      default: 'password',
      choices: [
        { name: 'Password', value: 'password' },
        { name: 'OTP', value: 'otp' },
        { name: 'Note', value: 'note' },
      ],
      required: true,
    },
    {
      name: 'protected',
      message: 'protected:',
      type: 'confirm',
      default: false,
      required: true,
    },
  ]);

  let newSecret = { typeOptions: {} };
  let encryptionKey = app.db.encryptionKey;

  if (info.protected) {
    encryptionKey = await getEncryptionKey(true);
  }

  switch (info.type) {
    case 'password':
      {
        const password = await prompt([
          {
            name: 'url',
            message: 'url:',
            type: 'input',
            required: false,
          },
          {
            name: 'username',
            message: 'username:',
            type: 'input',
            required: true,
          },
          {
            name: 'value',
            message: 'password:',
            type: 'password',
            required: true,
          },
        ]);
        newSecret = {
          ...info,
          value: password.value,
          typeOptions: {
            username: password.username,
            url: password.url,
          },
        };
      }

      break;
    case 'note':
      {
        const note = await prompt([
          {
            name: 'value',
            message: 'note:',
            type: 'password',
            required: true,
          },
        ]);
        newSecret = {
          ...info,
          value: note.value,
          typeOptions: {},
        };
      }

      break;
    case 'otp':
      {
        const otp = await prompt([
          {
            name: 'username',
            message: 'username:',
            type: 'input',
            required: true,
          },
          {
            name: 'value',
            message: 'value:',
            type: 'password',
            required: true,
          },
        ]);
        newSecret = {
          ...info,
          value: otp.value,
          typeOptions: {
            username: otp.username,
          },
        };
      }

      break;
  }

  await secrets.add(newSecret, encryptionKey);
};

export default wizard;
