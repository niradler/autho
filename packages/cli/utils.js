import inquirer from 'inquirer';
import OTP from 'sdk/otp.js';

export const prompt = inquirer.prompt;

export const ask = async ({ name = '', message = '', type = 'input' }) => {
  const answers = await inquirer.prompt([
    {
      name,
      message,
      type,
    },
  ]);

  return answers[name];
};

export const generateOTP = (secret) => {
  const otp = new OTP(secret);
  console.log('OTP code:', otp.generate());
};

