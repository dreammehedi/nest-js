import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { HydratedDocument } from "mongoose";
import { generateStringId } from "src/utils/utils";

export type BannerDocument = HydratedDocument<Banner>;

@Schema()
export class Banner {
    @Prop({ type: String, default: generateStringId })
    _id: string;

    @Prop({ type: String, default: '' })
    mediaUrl: string;

    @Prop({ type: Boolean, default: true })
    isActive: boolean;

    @Prop({ type: Boolean, default: false })
    isDeleted: boolean;

}

export const BannerSchema = SchemaFactory.createForClass(Banner);

BannerSchema.set('toJSON', {
    transform: function (doc, ret) {
        ret.id = ret._id;
        delete ret.__v;
        delete ret._id;
    },
});

BannerSchema.set('toObject', {
    transform: function (doc, ret) {
        ret.id = ret._id;
        delete ret.__v;
        delete ret._id;
    },
});

BannerSchema.set('timestamps', true);
