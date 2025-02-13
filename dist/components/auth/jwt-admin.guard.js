"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.JwtSuperAdminGuard = exports.JwtAdminGuard = void 0;
const common_1 = require("@nestjs/common");
const passport_1 = require("@nestjs/passport");
let JwtAdminGuard = class JwtAdminGuard extends (0, passport_1.AuthGuard)('jwt') {
    canActivate(context) {
        const { user } = context.switchToHttp().getRequest();
        return user.isAdmin;
    }
};
exports.JwtAdminGuard = JwtAdminGuard;
exports.JwtAdminGuard = JwtAdminGuard = __decorate([
    (0, common_1.Injectable)()
], JwtAdminGuard);
let JwtSuperAdminGuard = class JwtSuperAdminGuard extends (0, passport_1.AuthGuard)('jwt') {
    canActivate(context) {
        const { user } = context.switchToHttp().getRequest();
        return user.isSuperAdmin;
    }
};
exports.JwtSuperAdminGuard = JwtSuperAdminGuard;
exports.JwtSuperAdminGuard = JwtSuperAdminGuard = __decorate([
    (0, common_1.Injectable)()
], JwtSuperAdminGuard);
//# sourceMappingURL=jwt-admin.guard.js.map