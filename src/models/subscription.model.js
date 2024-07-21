import mongoose, { Schema, schema } from "mongoose";

const subscriptionSchema = new Schema(
    {
        subscriber: {
            type: Schema.Types.ObjectId,
            ref: "User",
        },
        chaneel: {
            type: Schema.Types.ObjectId,
            ref: "User",
        },
    },
    { timestamps: true }
);

export const Subscription = mongoose.Model("Subscription", subscriptionSchema);
