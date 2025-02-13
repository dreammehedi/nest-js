import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { User } from "src/decorators/user.decorator";
import { generateStringId } from "src/utils/utils";
import { Coin } from "../Coin/coin.schema";
import { HydratedDocument } from "mongoose";

export type UserStakeInfoDocument = HydratedDocument<UserStakeInfo>;

@Schema()
export class UserStakeInfo {
    @Prop({ type: String, default: generateStringId })
    _id: string;

    @Prop({ type: String, default: '', ref: User.name })
    userId: string;

    @Prop({ type: String, default: '', ref: Coin.name })
    coinId: string;

    @Prop({ type: Number, default: 0 })
    totalInvestments: number;

    @Prop({ type: Number, default: 0 })
    totalStaked: number;

    @Prop({ type: Number, default: 0 })
    totalRewards: number;

    @Prop({ type: Array<Number>, default: [] })
    investmentIds: number[];

    @Prop({ type: String, required: true, default: '', transform: (v) => v.toString().trim()?.toLowerCase() })
    stakingContractAddress: string;
}

export const UserStakeInfoSchema = SchemaFactory.createForClass(UserStakeInfo);

UserStakeInfoSchema.set('timestamps', true);

UserStakeInfoSchema.set('toJSON', {
    transform: (_, ret) => {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
    }
});

UserStakeInfoSchema.set('toObject', {
    transform: (_, ret) => {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
    }
});

UserStakeInfoSchema.index({ userId: 1 });
UserStakeInfoSchema.index({ coinId: 1 });
UserStakeInfoSchema.index({ totalStaked: 1 });
UserStakeInfoSchema.index({ totalRewards: 1 });
UserStakeInfoSchema.index({ stakingContractAddress: 1 });
UserStakeInfoSchema.index({ createdAt: 1 });
UserStakeInfoSchema.index({ updatedAt: 1 });
