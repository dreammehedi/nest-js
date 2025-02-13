import { ApiProperty } from "@nestjs/swagger";

export class WithdrawRewardDTO {
    @ApiProperty()
    coinId: string;

    @ApiProperty()
    investmentId: number;
}