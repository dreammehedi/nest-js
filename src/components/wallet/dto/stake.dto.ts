import { Prop } from "@nestjs/mongoose";
import { ApiProperty } from "@nestjs/swagger";
import { IsPositive } from "class-validator";

export class StakeDTO {
    @ApiProperty()
    coinId: string;

    @ApiProperty()
    @IsPositive()
    planId: number;

    @ApiProperty()
    @IsPositive()
    amount: number;
}