import { BadRequestException, Injectable } from '@nestjs/common';
import { SendEmailDTO } from './dto/email.dto';
import { NetworkDocument } from 'src/schema/Network/network.schema';
const SibApiV3Sdk = require('@getbrevo/brevo');


const formData = require('form-data');

@Injectable()
export class UtilsService {
  private apiInstance;
  constructor() {
    this.apiInstance = new SibApiV3Sdk.TransactionalEmailsApi();

    let apiKey = this.apiInstance.authentications['apiKey'];
    apiKey.apiKey = process.env.BREVO_API_KEY;
  }

  async sendEmail(emailDto: SendEmailDTO) {
    try {
      console.log(emailDto);
      let sendSmtpEmail = new SibApiV3Sdk.SendSmtpEmail();

      sendSmtpEmail.subject = emailDto?.subject;
      sendSmtpEmail.htmlContent = emailDto?.html;
      sendSmtpEmail.sender = { "name": "Mytsion", "email": emailDto?.from };
      sendSmtpEmail.to = emailDto?.to?.map((item) => ({ "email": item, name: item }))

      this.apiInstance.sendTransacEmail(sendSmtpEmail).then(function (data) {
        console.log('API called successfully. Returned data: ' + JSON.stringify(data));
      }, function (error) {
        console.error(error);
      });

      // return emailResponse
    }
    catch (err) {
      console.error(err);
      // throw new BadRequestException(err?.message);
    }
  }

  getTransactionHashUrl(network: NetworkDocument, trxHash: string) {
    try {
      if (network?.networkType === "EVM") {
        return `${network?.scanUrl}/tx/${trxHash}`
      } else if (network?.networkType === "BTC") {
        return `${network?.scanUrl}/tx/${trxHash}`
      } else if (network?.networkType === "TRON") {
        return `${network?.scanUrl}/#/transaction/${trxHash}`
      } else {
        return ""
      }
    } catch (error) {
      console.error(error);
      throw new Error(error);
    }
  }
}
