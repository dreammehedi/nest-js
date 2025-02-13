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
Object.defineProperty(exports, "__esModule", { value: true });
exports.UtilsService = void 0;
const common_1 = require("@nestjs/common");
const SibApiV3Sdk = require('@getbrevo/brevo');
const formData = require('form-data');
let UtilsService = class UtilsService {
    constructor() {
        this.apiInstance = new SibApiV3Sdk.TransactionalEmailsApi();
        let apiKey = this.apiInstance.authentications['apiKey'];
        apiKey.apiKey = process.env.BREVO_API_KEY;
    }
    async sendEmail(emailDto) {
        try {
            console.log(emailDto);
            let sendSmtpEmail = new SibApiV3Sdk.SendSmtpEmail();
            sendSmtpEmail.subject = emailDto?.subject;
            sendSmtpEmail.htmlContent = emailDto?.html;
            sendSmtpEmail.sender = { "name": "Mytsion", "email": emailDto?.from };
            sendSmtpEmail.to = emailDto?.to?.map((item) => ({ "email": item, name: item }));
            this.apiInstance.sendTransacEmail(sendSmtpEmail).then(function (data) {
                console.log('API called successfully. Returned data: ' + JSON.stringify(data));
            }, function (error) {
                console.error(error);
            });
        }
        catch (err) {
            console.error(err);
        }
    }
    getTransactionHashUrl(network, trxHash) {
        try {
            if (network?.networkType === "EVM") {
                return `${network?.scanUrl}/tx/${trxHash}`;
            }
            else if (network?.networkType === "BTC") {
                return `${network?.scanUrl}/tx/${trxHash}`;
            }
            else if (network?.networkType === "TRON") {
                return `${network?.scanUrl}/#/transaction/${trxHash}`;
            }
            else {
                return "";
            }
        }
        catch (error) {
            console.error(error);
            throw new Error(error);
        }
    }
};
exports.UtilsService = UtilsService;
exports.UtilsService = UtilsService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [])
], UtilsService);
//# sourceMappingURL=utils.service.js.map