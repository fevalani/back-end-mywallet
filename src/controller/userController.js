import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

import * as userRepository from "../repositories/userRepository.js";

async function signUp(req, res) {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.sendStatus(400);
    }

    const existingUserWithGivenEmail = await userRepository.getUserByEmail(
      email
    );

    if (existingUserWithGivenEmail.rows[0]) {
      return res.sendStatus(409);
    }

    const hashedPassword = bcrypt.hashSync(password, 12);

    await userRepository.insertUser(name, email, hashedPassword);

    res.sendStatus(201);
  } catch (err) {
    console.error(err);
    res.sendStatus(500);
  }
}

async function signIn(req, res) {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.sendStatus(400);
    }

    const user = await userRepository.getUserByEmail(email);

    if (!user.rows[0] || !bcrypt.compareSync(password, user.rows[0].password)) {
      return res.sendStatus(401);
    }

    const token = jwt.sign(
      {
        id: user.rows[0].id,
      },
      process.env.JWT_SECRET
    );

    res.send({
      token,
    });
  } catch (err) {
    console.error(err);
    res.sendStatus(500);
  }
}

export { signUp, signIn };
