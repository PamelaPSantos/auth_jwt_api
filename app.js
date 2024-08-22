//Imports
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

//Config JSON response
app.use(express.json());

//Models
const User = require("./models/User");

//Public route
app.get("/", (req, res) => {
  res.status(200).json({ message: "Bem-vindo a minha API" });
});

//Private route
app.get('/user/:id',checkToken, async(req, res) => {
    const id = req.params.id;

    //check if user exists
    const user = await User.findById(id, '-password')

    if(!user){
        return res.status(404).json({ message: "Usuário não encontrado!" });
    }
    res.status(200).json({ user });
})

function checkToken(req, res, next){
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if(!token) {
        return res.status(401).json({ message: "Acesso negado!" });
    }

    try{
        const secret = process.env.SECRET

        jwt.verify(token, secret)

        next()

    } catch(error){
        res.status(400).json({message: 'Token inválido!'})
    }
}

//Register user
app.post("/auth/register", async (req, res) => {
  const { name, email, password, confirmPassword } = req.body;

  //Validations
  if (!name) {
    return res.status(422).json({ message: "O nome é obrigatório!" });
  }

  if (!email) {
    return res.status(422).json({ message: "O email é obrigatório!" });
  }

  if (!password) {
    return res.status(422).json({ message: "A senha é obrigatória!" });
  }

  if (password != confirmPassword) {
    return res.status(422).json({ message: "As senhas não conferem!" });
  }

  //Check if user exists
  const userExists = await User.findOne({ email: email });

  if (userExists) {
    return res.status(422).json({ message: "Este email já está cadastrado!" });
  }

  //Create password
  const salt = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(password, salt);

  //Create user
  const user = new User({
    name,
    email,
    password: passwordHash,
  });

  try {
    await user.save();
    res.status(201).json({ message: "Usuário criado com sucesso!" });
  } catch (error) {
    console.log(error);
    res
      .status(500)
      .json({
        message: "Aconteceu um erro no servidor, tente novamente mais tarde",
      });
  }
});

//Login user
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  //Validations
  if (!email) {
    return res.status(422).json({ message: "O email é obrigatório!" });
  }

  if (!password) {
    return res.status(422).json({ message: "A senha é obrigatória!" });
  }

  //Check if user exists
  const user = await User.findOne({ email: email });

  if (!user) {
    return res.status(404).json({ message: "Usuário não encontrado!" });
  }

  //check if password match
  const checkPassword = await bcrypt.compare(password, user.password);

  if (!checkPassword) {
    return res.status(422).json({ message: "Senha inválida!" });
  }

  try {
    const secret = process.env.SECRET

    const token = jwt.sign({
        id: user._id,
    }, secret)
    res.status(200).json({ message: 'Usuário autenticado com sucesso!', token})

  } catch (err) {
    console.log(error);
    res
      .status(500)
      .json({
        message: "Aconteceu um erro no servidor, tente novamente mais tarde",
      });
  }
});

//Credencials
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose
  .connect(
    `mongodb+srv://${dbUser}:${dbPassword}@cluster0.h9q69.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`
  )
  .then(() => {
    app.listen(3000);
    console.log("Conectado ao banco!");
  })
  .catch((err) => {
    console.log(err);
  });
