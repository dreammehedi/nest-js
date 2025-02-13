import { NftService } from './nft.service';
export declare class NftController {
    private nftService;
    constructor(nftService: NftService);
    getNfts(limit: number, offset: number, user: any): Promise<any[]>;
    getNftById(id: string): Promise<any>;
}
