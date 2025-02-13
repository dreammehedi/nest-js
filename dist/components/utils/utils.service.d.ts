import { SendEmailDTO } from './dto/email.dto';
import { NetworkDocument } from 'src/schema/Network/network.schema';
export declare class UtilsService {
    private apiInstance;
    constructor();
    sendEmail(emailDto: SendEmailDTO): Promise<void>;
    getTransactionHashUrl(network: NetworkDocument, trxHash: string): string;
}
