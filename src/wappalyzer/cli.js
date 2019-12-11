#!/usr/bin/env node

/*
Author: Bugfix<tanjelly@gmail.com
Created: 2019-12-11
MOdified: 2019-12-11
*/

const Driver = require('./driver');
const fs = require("fs");
const path = require('path');
const args = process.argv.slice(2);

const ruleFile = args.shift() || '';
const url = args.shift() || '';
const headers = args.shift() || '';
const body = args.shift() || '';

if (!ruleFile || !url || !headers || !body) {
    process.stderr.write('Usage: node cli.js RULE_FILE URL HEADERS BODY [OPTIONS]\n');
    process.exit(1);
}

if (!ruleFile) {
    ruleFile = `${__dirname}/apps.json`;
}
fs.exists(ruleFile, function(exists) {
    if (!exists) {
        process.stderr.write('Wappalyzer rules file not found!\n');
        process.exit(1);
    }
});

if (!headers) {
    process.stderr.write('HEADERS parameter is null.\n');
    process.exit(1);
}

if (!body) {
    process.stderr.write('BODY parameter is null.\n');
    process.exit(1);
}

const options = {};
const rules = JSON.parse(fs.readFileSync(path.resolve(ruleFile)));

let arg;

do {
    arg = args.shift();

    const matches = /--([^=]+)=(.+)/.exec(arg);

    if (matches) {
        const key = matches[1].replace(/-\w/g, _matches => _matches[1].toUpperCase());
        const value = matches[2];

        options[key] = value;
    }
} while (arg);

const driver = new Driver(url, headers, body, rules, options);

driver.analyze()
    .then((json) => {
        process.stdout.write(`${JSON.stringify(json)}\n`);

        process.exit(0);
    })
    .catch((error) => {
        process.stderr.write(`${error}\n`);

        process.exit(1);
    });