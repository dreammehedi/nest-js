import { Prop } from "@nestjs/mongoose";
import { ApiProperty } from "@nestjs/swagger";
import { IsPositive } from "class-validator";

export class InvestAmountDTO {
    @ApiProperty()
    @IsPositive()
    planId: number;

    @ApiProperty()
    @IsPositive()
    amount: number;

    @ApiProperty()
    walletAddress: string;

    @ApiProperty()
    privateKey: string;
}