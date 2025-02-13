import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { HydratedDocument } from "mongoose";
import { generateStringId } from "src/utils/utils";

export type DonationOrganizationDocument = HydratedDocument<DonationOrganization>;

@Schema()
export class DonationOrganization {
    @Prop({ type: String, default: generateStringId })
    _id: string;

    @Prop({ type: String, default: '' })
    name: string;

    @Prop({ type: String, default: '' })
    walletAddress: string;

    @Prop({ type: Boolean, default: true })
    isActive: boolean;

    @Prop({ type: Boolean, default: false })
    isDeleted: boolean;
}

export const DonationOrganizationSchema = SchemaFactory.createForClass(DonationOrganization);

DonationOrganizationSchema.set('timestamps', true);

DonationOrganizationSchema.set('toJSON', {
    transform: function (doc, ret) {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
    },
});

DonationOrganizationSchema.set('toObject', {
    transform: function (doc, ret) {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
    },
});

DonationOrganizationSchema.index({ name: 1 });
DonationOrganizationSchema.index({ walletAddress: 1 });

