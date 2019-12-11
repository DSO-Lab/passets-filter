const Driver = require('./driver');

class Wappalyzer {
    constructor(url, headers, body, rules, options) {
        return new Driver(url, headers, body, rules, options);
    }
}

module.exports = Wappalyzer;