import inquirer from 'inquirer';

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
