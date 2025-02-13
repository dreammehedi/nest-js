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
export type NFTDocument = HydratedDocument<NFT>;
export declare class NFT {
    _id: string;
    name: string;
    symbol: string;
    tokenId: string;
    walletId: string;
    userId: string;
    owner: string;
    type: string;
    networkId: string;
    tokenUri: string;
    contractAddress: string;
    amount: number;
    imageUrl: string;
}
export declare const NFTSchema: import("mongoose").Schema<NFT, import("mongoose").Model<NFT, any, any, any, import("mongoose").Document<unknown, any, NFT> & NFT & Required<{
    _id: string;
}>, any>, {}, {}, {}, {}, import("mongoose").DefaultSchemaOptions, NFT, import("mongoose").Document<unknown, {}, NFT> & NFT & Required<{
    _id: string;
}>>;
