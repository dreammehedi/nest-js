import { MediaUploadService } from './media-upload.service';
export declare class MediaUploadController {
    private _mediaUploadService;
    constructor(_mediaUploadService: MediaUploadService);
    uploadAvatar(file: any, folderName: string, req: any): Promise<any>;
    mediaFiles(folderName: string, fileName: string, res: any, req: any, size?: string): Promise<any>;
}
