var encode = require('./functions/encode.js');
var address = require('./functions/address.js');
var constants = require('./constants.js');









module.exports = {
    functions: {address: address,
                encode: encode,
                constants:constants
    }

};