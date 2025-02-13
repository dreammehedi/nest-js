import { Transform } from 'class-transformer';

const ToBoolean = () => {
    const toPlain = Transform(
        ({ value }) => {
            return value;
        },
        {
            toPlainOnly: true,
        }
    );
    const toClass = (target: any, key: string) => {
        return Transform(
            ({ obj }) => {
                return valueToBoolean(obj[key]);
            },
            {
                toClassOnly: true,
            }
        )(target, key);
    };
    return function (target: any, key: string) {
        toPlain(target, key);
        toClass(target, key);
    };
};

const valueToBoolean = (value: any) => {
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
    return obj
};

const getSchemaProjection = (className) => {
    let projection = {}
    
    Object.keys(className).forEach( (key) => {
        if(key == '_id') {
            projection['id'] = '$id'
        } else {
            projection[key] = 1
        }
    })
    return projection;
};

// const getSchemaProjection = (schemaClass) => {
//     let filter = {

//     }
//     for Obj
// }

export const generateReferralCode = () => {
    let random = Math.random().toString(36).slice(2)
    return random.toUpperCase();
}

export const generateUsername = (fullname) => {
    let randomNumbers = [];
    
    let i = 0;
    while (i < 5) {
        let digits = Math.floor((Math.random()*3))+1;
        let randomNumber = Math.floor(Math.random()*(10**digits))
        randomNumbers.push(fullname + randomNumber);
        i++;
    }

    return randomNumbers;
}

const addDaysToDate = (date, days) => {
    date.setDate(date.getDate() + days)
  
    return date
  }
  

export { ToBoolean, cleanObject, getSchemaProjection, addDaysToDate };