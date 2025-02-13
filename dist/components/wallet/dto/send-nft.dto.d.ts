export declare enum NftType {
    ERC721 = "ERC721",
    ERC1155 = "ERC1155"
}
export declare class SendNftDTO {
    nftAddress: string;
    toAddress: string;
    tokenId: string;
    type: NftType;
    amount: number;
    networkId: string;
}
