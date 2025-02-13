"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthController = void 0;
const common_1 = require("@nestjs/common");
const auth_service_1 = require("./auth.service");
const login_dto_1 = require("./dto/login.dto");
const otp_dto_1 = require("./dto/otp.dto");
const signup_dto_1 = require("./dto/signup.dto");
const swagger_1 = require("@nestjs/swagger");
const email_dto_1 = require("./dto/email.dto");
const password_dto_1 = require("./dto/password.dto");
const jwt_auth_guard_1 = require("./jwt-auth.guard");
const user_decorator_1 = require("../../decorators/user.decorator");
const profile_dto_1 = require("./dto/profile.dto");
const users_dto_1 = require("./dto/users.dto");
const jwt_admin_guard_1 = require("./jwt-admin.guard");
const banner_dto_1 = require("./dto/banner.dto");
let AuthController = class AuthController {
    constructor(authService) {
        this.authService = authService;
    }
    signup(signupDto) {
        signupDto.isAdmin = false;
        return this.authService.signup(signupDto);
    }
    signupAdmin(signupDto) {
        signupDto.isAdmin = true;
        return this.authService.signup(signupDto);
    }
    verifyEmail(otpDto) {
        return this.authService.verifyEmail(otpDto);
    }
    resendOtp(emailDto) {
        return this.authService.resendOtp(emailDto);
    }
    login(loginDto) {
        return this.authService.login(loginDto);
    }
    forgotPassword(emailDto) {
        return this.authService.forgotPassword(emailDto);
    }
    verifyOtpForForgotPassword(otpDto) {
        return this.authService.verifyOtpForForgotPassword(otpDto);
    }
    resetPassword(passwordDto, user) {
        return this.authService.resetPassword(passwordDto, user);
    }
    changePassword(changePasswordDTO, user) {
        return this.authService.changePassword(changePasswordDTO, user);
    }
    changeEmail(changeEmailDTO, user) {
        return this.authService.changeEmail(changeEmailDTO, user);
    }
    updateProfile(updateProfile, user) {
        return this.authService.updateProfile(updateProfile, user.id);
    }
    getLoggedInUsers(user) {
        return this.authService.getLoggedInUsers(user);
    }
    deleteUser(user) {
        return this.authService.deleteUser(user?.id);
    }
    getAllUsers(User, getUsersDTO) {
        return this.authService.getAllUsers(User?.id, getUsersDTO);
    }
    updateUserActive(updateUserActiveDTO) {
        return this.authService.updateUserActive(updateUserActiveDTO);
    }
    updateUserRole(updateUserRoleDTO) {
        return this.authService.updateUserRole(updateUserRoleDTO);
    }
    addBanner(addBannerDTO) {
        return this.authService.addBanner(addBannerDTO);
    }
    updateBanner(updateBannerDTO) {
        return this.authService.updateBanner(updateBannerDTO);
    }
    getBanners(getBannerDTO) {
        return this.authService.getBanners(getBannerDTO);
    }
};
exports.AuthController = AuthController;
__decorate([
    (0, common_1.Post)('signup'),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [signup_dto_1.SignupDTO]),
    __metadata("design:returntype", void 0)
], AuthController.prototype, "signup", null);
__decorate([
    (0, common_1.Post)('signupAdmin'),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [signup_dto_1.SignupDTO]),
    __metadata("design:returntype", void 0)
], AuthController.prototype, "signupAdmin", null);
__decorate([
    (0, common_1.Post)('verifyEmail'),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [otp_dto_1.OtpDTO]),
    __metadata("design:returntype", void 0)
], AuthController.prototype, "verifyEmail", null);
__decorate([
    (0, common_1.Post)('resendOtp'),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [email_dto_1.EmailDTO]),
    __metadata("design:returntype", void 0)
], AuthController.prototype, "resendOtp", null);
__decorate([
    (0, common_1.Post)('login'),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [login_dto_1.LoginDTO]),
    __metadata("design:returntype", void 0)
], AuthController.prototype, "login", null);
__decorate([
    (0, common_1.Post)('forgotPassword'),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [email_dto_1.EmailDTO]),
    __metadata("design:returntype", void 0)
], AuthController.prototype, "forgotPassword", null);
__decorate([
    (0, common_1.Post)('verifyOtpForForgotPassword'),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [otp_dto_1.OtpDTO]),
    __metadata("design:returntype", void 0)
], AuthController.prototype, "verifyOtpForForgotPassword", null);
__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard),
    (0, common_1.Post)('resetPassword'),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, user_decorator_1.User)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [password_dto_1.PasswordDTO, Object]),
    __metadata("design:returntype", void 0)
], AuthController.prototype, "resetPassword", null);
__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard),
    (0, common_1.Post)('changePassword'),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, user_decorator_1.User)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [password_dto_1.ChangePasswordDTO, Object]),
    __metadata("design:returntype", void 0)
], AuthController.prototype, "changePassword", null);
__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard),
    (0, common_1.Post)('changeEmail'),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, user_decorator_1.User)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [password_dto_1.ChangeEmailDTO, Object]),
    __metadata("design:returntype", void 0)
], AuthController.prototype, "changeEmail", null);
__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard),
    (0, common_1.Post)('updateProfile'),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, user_decorator_1.User)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [profile_dto_1.UpdateProfileDTO, Object]),
    __metadata("design:returntype", void 0)
], AuthController.prototype, "updateProfile", null);
__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard),
    (0, common_1.Get)('getLoggedInUser'),
    __param(0, (0, user_decorator_1.User)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", void 0)
], AuthController.prototype, "getLoggedInUsers", null);
__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard),
    (0, common_1.Get)('deleteUser'),
    __param(0, (0, user_decorator_1.User)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", void 0)
], AuthController.prototype, "deleteUser", null);
__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, common_1.UseGuards)(jwt_admin_guard_1.JwtAdminGuard),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard),
    (0, swagger_1.ApiQuery)({ name: 'limit', required: false, type: Number, example: 10 }),
    (0, swagger_1.ApiQuery)({ name: 'offset', required: false, type: Number, example: 0 }),
    (0, common_1.Get)('getAllUsers'),
    __param(0, (0, user_decorator_1.User)()),
    __param(1, (0, common_1.Query)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, users_dto_1.GetUsersDTO]),
    __metadata("design:returntype", void 0)
], AuthController.prototype, "getAllUsers", null);
__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, common_1.UseGuards)(jwt_admin_guard_1.JwtAdminGuard),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard),
    (0, common_1.Post)('updateUserActive'),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [users_dto_1.UpdateUserActiveDTO]),
    __metadata("design:returntype", void 0)
], AuthController.prototype, "updateUserActive", null);
__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, common_1.UseGuards)(jwt_admin_guard_1.JwtAdminGuard),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard),
    (0, common_1.Post)('updateUserRole'),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [users_dto_1.UpdateUserRoleDTO]),
    __metadata("design:returntype", void 0)
], AuthController.prototype, "updateUserRole", null);
__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, common_1.UseGuards)(jwt_admin_guard_1.JwtAdminGuard),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard),
    (0, common_1.Post)('addBanner'),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [banner_dto_1.AddBannerDTO]),
    __metadata("design:returntype", void 0)
], AuthController.prototype, "addBanner", null);
__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, common_1.UseGuards)(jwt_admin_guard_1.JwtAdminGuard),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard),
    (0, common_1.Post)('updateBanner'),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [banner_dto_1.UpdateBannerDTO]),
    __metadata("design:returntype", void 0)
], AuthController.prototype, "updateBanner", null);
__decorate([
    (0, swagger_1.ApiBearerAuth)(),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard),
    (0, common_1.Get)('getBanners'),
    __param(0, (0, common_1.Query)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [banner_dto_1.GetBannerDTO]),
    __metadata("design:returntype", void 0)
], AuthController.prototype, "getBanners", null);
exports.AuthController = AuthController = __decorate([
    (0, swagger_1.ApiTags)('Auth'),
    (0, common_1.Controller)('auth'),
    __metadata("design:paramtypes", [auth_service_1.AuthService])
], AuthController);
//# sourceMappingURL=auth.controller.js.map