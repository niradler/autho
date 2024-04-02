import { prompt } from "../utils.js";
import Secrets from "../../sdk/secrets.js";

const wizard = async (config, masterPasswordHash) => {
  const info = await prompt([
    {
      name: "name",
      message: "name:",
      type: "input",
      required: true,
    },
    {
      name: "type",
      message: "type:",
      type: "list",
      default: "password",
      choices: ["password", "otp", "note"],
      required: true,
    }
  ]);

  let newSecret = {};

  switch (info.type) {
    case "password":
      const password = await prompt([
        {
          name: "username",
          message: "username:",
          type: "input",
          required: true,
        },
        {
          name: "value",
          message: "password:",
          type: "password",
          required: true,
        },
      ]);
      newSecret = {
        name: info.name,
        type: info.type,
        value: password.value,
        typeOptions: {
          username: password.username,
        },
      };
      break;
    case "note":
      const note = await prompt([
        {
          name: "value",
          message: "note:",
          type: "password",
          required: true,
        },
      ]);
      newSecret = {
        name: info.name,
        type: info.type,
        value: note.value,
        typeOptions: {

        },
      };
      break;
    case "otp":
      const otp = await prompt([
        {
          name: "username",
          message: "username:",
          type: "input",
          required: true,
        },
        {
          name: "value",
          message: "value:",
          type: "password",
          required: true,
        },
      ]);
      newSecret = {
        name: info.name,
        type: info.type,
        value: otp.value,
        typeOptions: {
          username: otp.username,
        },
      };
      break;
  }

  const secrets = new Secrets(config);
  await secrets.add(newSecret, masterPasswordHash);
};

export default wizard;
