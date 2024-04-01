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
      type: "choice",
      default: "otp",
      choices: ["otp"],
      required: true,
    }
  ]);

  let newSecret = {};

  switch (info.type) {
    case "otp":
        const secret = await prompt([
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
            value: secret.value,
            typeOptions: {
              username: secret.username,
            },
          };
      break;
  }

  const secrets = new Secrets(config);
  await secrets.add(newSecret, masterPasswordHash);
};

export default wizard;
