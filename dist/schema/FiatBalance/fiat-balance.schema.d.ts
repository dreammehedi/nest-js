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
export type FiatBalanceDocument = HydratedDocument<FiatBalance>;
export declare class FiatBalance {
    _id: string;
    userId: string;
    walletId: string;
    currencyId: string;
    balance: number;
    totalWithdrawnAmount: number;
    totalWithdrawnAmountLocked: number;
}
export declare const FiatBalanceSchema: import("mongoose").Schema<FiatBalance, import("mongoose").Model<FiatBalance, any, any, any, import("mongoose").Document<unknown, any, FiatBalance> & FiatBalance & Required<{
    _id: string;
}>, any>, {}, {}, {}, {}, import("mongoose").DefaultSchemaOptions, FiatBalance, import("mongoose").Document<unknown, {}, FiatBalance> & FiatBalance & Required<{
    _id: string;
}>>;
