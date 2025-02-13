import { ApiProperty } from '@nestjs/swagger';
import { CoinNetworkDTO } from './coinNetwork.dto';
import { IsPositive } from 'class-validator';

export class WithdrawDTO extends CoinNetworkDTO {
  @ApiProperty()
  address: string;
  @ApiProperty()
  @IsPositive()
  amount: number;
}

export class SwapDTO extends CoinNetworkDTO {
  @ApiProperty()
  @IsPositive()
  amount: number;

  @ApiProperty()
  currencyId: string;
}

export class WithdrawFiatDTO {
  @ApiProperty()
  @IsPositive()
  amount: number;
  @ApiProperty()
  currencyId: string;
  @ApiProperty({ required: true })
  bankName?: string;
  @ApiProperty({ required: true })
  accountNumber?: string;
  @ApiProperty({ required: true })
  accountName?: string;

  @ApiProperty({ required: false })
  country?: string;
}
