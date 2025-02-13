export declare class AddBannerDTO {
    mediaUrl: string;
}
export declare class UpdateBannerDTO {
    bannerId: string;
    mediaUrl: string;
    isActive: boolean;
    isDeleted: boolean;
}
export declare class GetBannerDTO {
    isDeleted: any;
    isActive: any;
    limit: number;
    offset: number;
}
