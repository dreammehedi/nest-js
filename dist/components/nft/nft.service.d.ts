import { Model } from 'mongoose';
import { NetworkDocument } from 'src/schema/Network/network.schema';
import { NFTDocument } from 'src/schema/Nft/nft.schema';
import { UserDocument } from 'src/schema/User/user.schema';
import { WalletDocument } from 'src/schema/Wallet/wallet.schema';
export declare class NftService {
    private readonly nftModel;
    private readonly networkModel;
    private readonly walletModel;
    private readonly userModel;
    constructor(nftModel: Model<NFTDocument>, networkModel: Model<NetworkDocument>, walletModel: Model<WalletDocument>, userModel: Model<UserDocument>);
    getAllNftFromWallet(wallet: WalletDocument, network: NetworkDocument, user: UserDocument): Promise<any>;
    readNftForAllUsers(): Promise<void>;
    readNftForUser(userId: any): Promise<void>;
    getNfts(limit: any, offset: any, user: any): Promise<any[]>;
    getNftById(id: any): Promise<any>;
}
