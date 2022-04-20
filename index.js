const express = require("express");
const { dbConnect } = require("./config/dbConnect");
const productRouter = require("./routes/products.router");

const app = express();
app.use(express.json());

app.use("/products", productRouter);

const start = async () => {
  await dbConnect();

  app.listen(4000, () => {
    console.log("server is up and running");
  });
};

start();
