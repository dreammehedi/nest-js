import { ApiProperty } from "@nestjs/swagger";
import { IsBoolean, IsOptional, IsString } from "class-validator";

export class AddBannerDTO {

    @ApiProperty({required: true, type: String})
    @IsString()
    mediaUrl: string;

}

export class UpdateBannerDTO {

    @ApiProperty({required: true, type: String})
    @IsOptional()
    @IsString()
    bannerId: string;

    @ApiProperty({required: false, type: String})
    @IsOptional()
    @IsString()
    mediaUrl: string;

    @ApiProperty({required: false, type: Boolean})
    @IsOptional()
    @IsBoolean()
    isActive: boolean;

    @ApiProperty({required: false, type: Boolean})
    @IsOptional()
    @IsBoolean()
    isDeleted: boolean;

}

export class GetBannerDTO {

    @ApiProperty({ type: Boolean, required: false, default: null })
    isDeleted: any;
    
    @ApiProperty({ type: Boolean, required: false, default: null })
    isActive: any;

    @ApiProperty({ type: Number, required: false, default: 10 })
    @IsOptional()
    limit: number;

    @ApiProperty({ type: Number, required: false, default: 0 })
    @IsOptional()
    offset: number;
}
