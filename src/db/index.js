import mongoose from "mongoose";
import { DB_NAME } from "../constants.js";

const connectDB = async () => {
    try {
        const connnectionInstance = await mongoose.connect(
            `${process.env.DB_URL}/${DB_NAME}`
        );
        console.log(connnectionInstance.connection.host);
    } catch (error) {
        console.log("MongoDB connnection Failed ", error);
        process.exit(1);
    }
};

export default connectDB;
