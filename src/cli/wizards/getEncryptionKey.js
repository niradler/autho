import Cipher from "../../sdk/cipher.js";
import { prompt } from "../utils.js";

const wizard = async (confirm = false) => {
  const questions = [{
    name: "password",
    message: "password:",
    type: "password",
    required: true,
  }
  ]
  if (confirm) {
    questions.push({
      name: "confirmPassword",
      message: "confirm password:",
      type: "password",
      required: true,
    });
  }
  const input = await prompt(questions);

  if (input.confirmPassword && input.password !== input.confirmPassword) {
    throw new Error("Passwords do not match");
  }

  return Cipher.hash(input.password);
}


export default wizard;