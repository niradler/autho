import { prompt } from "../utils.js";

const wizard = async (app) => {
  const existingSecrets = app.db.get("secrets", []);

  if (existingSecrets.length === 0) {
    throw new Error("No secrets found");
  }

  const choices = existingSecrets.map((secret) => ({
    value: secret.id,
    name: `${secret.name} (${secret.typeOptions.username || secret.id})`,
  }));

  const { id: secretId } = await prompt({
    name: "id",
    message: "Secrets:",
    type: "list",
    choices,
    required: true,
  });
  const secret = await app.secrets.get(secretId);

  if (!secret) {
    throw new Error("Secret not found");
  }

  return secret;
};

export default wizard;
