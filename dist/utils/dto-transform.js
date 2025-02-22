"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.addDaysToDate = exports.getSchemaProjection = exports.cleanObject = exports.ToBoolean = exports.generateUsername = exports.generateReferralCode = void 0;
const class_transformer_1 = require("class-transformer");
const ToBoolean = () => {
    const toPlain = (0, class_transformer_1.Transform)(({ value }) => {
        return value;
    }, {
        toPlainOnly: true,
    });
    const toClass = (target, key) => {
        return (0, class_transformer_1.Transform)(({ obj }) => {
            return valueToBoolean(obj[key]);
        }, {
            toClassOnly: true,
        })(target, key);
    };
    return function (target, key) {
        toPlain(target, key);
        toClass(target, key);
    };
};
exports.ToBoolean = ToBoolean;
const valueToBoolean = (value) => {
    if (value === null || value === undefined) {
        return undefined;
    }
    if (typeof value === 'boolean') {
        return value;
    }
    if (['true', 'on', 'yes', '1'].includes(value.toLowerCase())) {
        return true;
    }
    if (['false', 'off', 'no', '0'].includes(value.toLowerCase())) {
        return false;
    }
    return undefined;
};
const cleanObject = (obj) => {
    for (var propName in obj) {
        if (obj[propName] === null || obj[propName] === undefined || obj[propName] === "") {
            delete obj[propName];
        }
    }
    return obj;
};
exports.cleanObject = cleanObject;
const getSchemaProjection = (className) => {
    let projection = {};
    Object.keys(className).forEach((key) => {
        if (key == '_id') {
            projection['id'] = '$id';
        }
        else {
            projection[key] = 1;
        }
    });
    return projection;
};
exports.getSchemaProjection = getSchemaProjection;
const generateReferralCode = () => {
    let random = Math.random().toString(36).slice(2);
    return random.toUpperCase();
};
exports.generateReferralCode = generateReferralCode;
const generateUsername = (fullname) => {
    let randomNumbers = [];
    let i = 0;
    while (i < 5) {
        let digits = Math.floor((Math.random() * 3)) + 1;
        let randomNumber = Math.floor(Math.random() * (10 ** digits));
        randomNumbers.push(fullname + randomNumber);
        i++;
    }
    return randomNumbers;
};
exports.generateUsername = generateUsername;
const addDaysToDate = (date, days) => {
    date.setDate(date.getDate() + days);
    return date;
};
exports.addDaysToDate = addDaysToDate;
//# sourceMappingURL=dto-transform.js.map