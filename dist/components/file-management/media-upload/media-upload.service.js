"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.MediaUploadService = void 0;
const common_1 = require("@nestjs/common");
const jimp = require('jimp');
const fs = require("fs");
let MediaUploadService = class MediaUploadService {
    async compressImageTo300(file) {
        const img = await jimp.read(file['path']);
        const height = img.bitmap.height;
        const width = img.bitmap.width;
        if ((height < 200 && width < 300) || file.size <= 300 * 1000) {
            return '';
        }
        const heightRatio = height / width;
        const widthRatio = width / height;
        file['path'] = file['path'].replace('compressed', `300`);
        img.resize(300 * widthRatio, jimp.AUTO).write(file['path']);
    }
    async compressFolder(folderName) {
        try {
            const basePath = 'mediaFiles/metasuite/' + folderName;
            const files = fs.readdirSync(basePath);
            for await (const fileItem of files) {
                const allowTypes = ['.jpg', '.jpeg', '.png'];
                let type = '';
                const nameSplit = fileItem.split('.');
                if (nameSplit.length > 1) {
                    type = nameSplit[1];
                }
                let filePath = basePath + '/' + fileItem;
                if (type && allowTypes.includes(`.${type}`)) {
                    const img = await jimp.read(filePath);
                    const height = img.bitmap.height;
                    const width = img.bitmap.width;
                    const heightRatio = height / width;
                    const widthRatio = width / height;
                    filePath = filePath.replace(fileItem, `compressed/${fileItem}`);
                    await img.resize(500 * widthRatio, jimp.AUTO).write(filePath);
                }
            }
        }
        catch (err) {
            console.log(err);
            throw new common_1.BadRequestException(err?.message);
        }
    }
};
exports.MediaUploadService = MediaUploadService;
exports.MediaUploadService = MediaUploadService = __decorate([
    (0, common_1.Injectable)()
], MediaUploadService);
//# sourceMappingURL=media-upload.service.js.map