import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";

const app = express();

// middleware to allow access to only limited users
app.use(
    cors({
        origin: process.env.CORS_ORIGIN,
        credentials: true,
    })
);

//common middlewares

app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(express.static("public"));
app.use(cookieParser());

//routes
import userRoute from "./routes/user.routes.js";

app.use("/api/v1/users", userRoute);

export { app };
