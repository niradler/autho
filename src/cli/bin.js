#!/usr/bin/env node

import { Command } from "commander";
import chalk from "chalk";
import { prompt, ask } from "./utils.js";
import Config from "../sdk/config.js";
import Cipher from "../sdk/cipher.js";
import createSecret from "./wizards/createSecret.js";
import Secrets from "../sdk/secrets.js";
import OTP from "../sdk/otp.js";

const program = new Command();

const getSecret = async (config) => {
  const existingSecrets = config.get("secrets", []);

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
  const secrets = new Secrets(config);
  const secret = await secrets.get(secretId);

  if (!secret) {
    throw new Error("Secret not found");
  }

  return secret;
};

program
  .name("autho")
  .description("Secrets manager")
  .version("0.0.1")
  .option("-p, --password <password>", "Master password")
  .action(async (args) => {
    try {
      const masterPassword = args.password
        ? args.password
        : await ask({
          name: "masterPassword",
          message: "Password:",
          type: "password",
          required: true,
        });
      const masterPasswordHash = Cipher.hash(masterPassword);
      const config = new Config({ encryptionKey: masterPasswordHash });

      let choices = [
        { value: "create", name: "Create new secret" },
        { value: "read", name: "Read secret" },
        { value: "delete", name: "Delete secret" },
      ];

      const { action } = await prompt({
        name: "action",
        type: "list",
        choices,
        required: true,
      });
      switch (action) {
        case "create":
          await createSecret(config, masterPasswordHash);
          break;

        case "read":
          const readSecret = await getSecret(config);
          readSecret.value = Cipher.decrypt(readSecret.value, readSecret.publicKey, masterPasswordHash)

          switch (readSecret.type) {
            case "password":
              console.log("Username:", readSecret.typeOptions.username);
              console.log("Password:", readSecret.value);
              break;
            case "note":
              console.log("Note:", readSecret.value);
              break;
            case "otp":
              const otp = new OTP(readSecret);
              console.log("OTP code:", otp.generate());
              setTimeout(() => {
                console.log("Expired");
                process.exit(0);
              }, 30000);
              break;
          }

          break;
        case "delete":
          const deleteSecret = await getSecret(config);
          const secrets = new Secrets(config);
          await secrets.remove(deleteSecret.id)
          console.log("Removed");
          process.exit(0);
          break;
      }
    } catch (error) {
      console.log(
        chalk.redBright("Something went wrong, Error: "),
        error.message
      );
      console.log(error.stack);
      process.exit(1);
    }
  });

program.parse();
