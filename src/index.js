import connectDB from "./db/index.js";
import dotenv from "dotenv";
import { app } from "./app.js";

dotenv.config({
    path: "./.env",
});

connectDB()
    .then(() => {
        app.listen(process.env.PORT || 3000, () => {
            console.log("Server is running on port ", process.env.PORT);
        });
        app.on("error", (error) => {
            console.log("Error while connection to app ", error);
        });
    })
    .catch((err) => {
        console.log("MONGO DB connection failed ", err);
    });
