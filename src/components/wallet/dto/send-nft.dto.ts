import { ApiProperty } from '@nestjs/swagger';

export enum NftType {
  ERC721 = 'ERC721',
  ERC1155 = 'ERC1155',
}

export class SendNftDTO {
  @ApiProperty()
  nftAddress: string;
  @ApiProperty()
  toAddress: string;
  @ApiProperty()
  tokenId: string;
  @ApiProperty()
  type: NftType;
  @ApiProperty()
  amount: number;
  @ApiProperty()
  networkId: string;
}
