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
import { HydratedDocument } from 'mongoose';
export type NetworkDocument = HydratedDocument<Network>;
export declare class Network {
    _id: string;
    name: string;
    symbol: string;
    logoUrl: string;
    rpcUrl: string;
    chainId: number;
    nativeCoinAddress: string;
    networkName: string;
    networkType: string;
    scanUrl: string;
    isMainnet: boolean;
    isDeleted: boolean;
    isActive: boolean;
}
export declare const NetworkSchema: import("mongoose").Schema<Network, import("mongoose").Model<Network, any, any, any, import("mongoose").Document<unknown, any, Network> & Network & Required<{
    _id: string;
}>, any>, {}, {}, {}, {}, import("mongoose").DefaultSchemaOptions, Network, import("mongoose").Document<unknown, {}, Network> & Network & Required<{
    _id: string;
}>>;
