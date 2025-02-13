export declare class GetUsersDTO {
    limit: string;
    offset: string;
    filterOnlyAdmins: any;
}
export declare class UpdateUserActiveDTO {
    userId: string;
    isActive?: boolean;
}
export declare class UpdateUserRoleDTO {
    userId: string;
    role?: string;
}
