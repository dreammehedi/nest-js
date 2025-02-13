import { ExecutionContext } from '@nestjs/common';
declare const JwtAdminGuard_base: import("@nestjs/passport").Type<import("@nestjs/passport").IAuthGuard>;
export declare class JwtAdminGuard extends JwtAdminGuard_base {
    canActivate(context: ExecutionContext): boolean;
}
declare const JwtSuperAdminGuard_base: import("@nestjs/passport").Type<import("@nestjs/passport").IAuthGuard>;
export declare class JwtSuperAdminGuard extends JwtSuperAdminGuard_base {
    canActivate(context: ExecutionContext): boolean;
}
export {};
