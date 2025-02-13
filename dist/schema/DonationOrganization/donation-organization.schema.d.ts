/// <reference types="mongoose/types/aggregate" />
/// <reference types="mongoose/types/callback" />
/// <reference types="mongoose/types/collection" />
/// <reference types="mongoose/types/connection" />
/// <reference types="mongoose/types/cursor" />
/// <reference types="mongoose/types/document" />
/// <reference types="mongoose/types/error" />
/// <reference types="mongoose/types/expressions" />
/// <reference types="mongoose/types/helpers" />
/// <reference types="mongoose/types/middlewares" />
/// <reference types="mongoose/types/indexes" />
/// <reference types="mongoose/types/models" />
/// <reference types="mongoose/types/mongooseoptions" />
/// <reference types="mongoose/types/pipelinestage" />
/// <reference types="mongoose/types/populate" />
/// <reference types="mongoose/types/query" />
/// <reference types="mongoose/types/schemaoptions" />
/// <reference types="mongoose/types/schematypes" />
/// <reference types="mongoose/types/session" />
/// <reference types="mongoose/types/types" />
/// <reference types="mongoose/types/utility" />
/// <reference types="mongoose/types/validation" />
/// <reference types="mongoose/types/virtuals" />
/// <reference types="mongoose/types/inferschematype" />
import { HydratedDocument } from "mongoose";
export type DonationOrganizationDocument = HydratedDocument<DonationOrganization>;
export declare class DonationOrganization {
    _id: string;
    name: string;
    walletAddress: string;
    isActive: boolean;
    isDeleted: boolean;
}
export declare const DonationOrganizationSchema: import("mongoose").Schema<DonationOrganization, import("mongoose").Model<DonationOrganization, any, any, any, import("mongoose").Document<unknown, any, DonationOrganization> & DonationOrganization & Required<{
    _id: string;
}>, any>, {}, {}, {}, {}, import("mongoose").DefaultSchemaOptions, DonationOrganization, import("mongoose").Document<unknown, {}, DonationOrganization> & DonationOrganization & Required<{
    _id: string;
}>>;
