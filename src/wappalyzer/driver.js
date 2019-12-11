/*
Author: Bugfix<tanjelly@gmail.com
Created: 2019-12-11
MOdified: 2019-12-11
*/

const url = require('url');
const iconv = require('iconv-lite');
const detect = require('charset-detector');
const Wappalyzer = require('./wappalyzer');

const errorTypes = {
    RESPONSE_NOT_OK: 'Response was not ok',
    NO_RESPONSE: 'No response from server',
    NO_HTML_DOCUMENT: 'No HTML document',
    IGNORE_TYPE: 'Ignore Content-Type'
};

function sleep(ms) {
    return ms ? new Promise(resolve => setTimeout(resolve, ms)) : Promise.resolve();
}

function processHtml(html, maxCols, maxRows) {
    if (maxCols || maxRows) {
        const chunks = [];
        const rows = html.length / maxCols;

        let i;

        for (i = 0; i < rows; i += 1) {
            if (i < maxRows / 2 || i > rows - maxRows / 2) {
                chunks.push(html.slice(i * maxCols, (i + 1) * maxCols));
            }
        }

        html = chunks.join('\n');
    }

    return html;
}

class Driver {
    constructor(pageUrl, pageHeaders, pageContent, rules, options) {
        this.options = Object.assign({}, {
            debug: false,
            delay: 500,
            htmlMaxCols: 2000,
            htmlMaxRows: 3000
        }, options || {});

        this.options.debug = Boolean(+this.options.debug);
        this.options.delay = this.options.recursive ? parseInt(this.options.delay, 10) : 0;
        this.options.htmlMaxCols = parseInt(this.options.htmlMaxCols, 10);
        this.options.htmlMaxRows = parseInt(this.options.htmlMaxRows, 10);

        this.origPageUrl = url.parse(pageUrl);
        this.origPageHeaders = this.decodeData(pageHeaders).trim();
        this.origPageContent = this.decodeData(pageContent).trim();
        this.analyzedPageUrls = {};
        this.apps = [];

        this.statusCode = 0;
        this.contentType = null;
        this.links = [];
        this.scripts = [];

        this.meta = {};
        this.headers = {};
        this.rawHeaders = pageHeaders;
        this.html = '';

        this.listeners = {};
        this.wappalyzer = new Wappalyzer();

        this.wappalyzer.apps = rules.apps;
        this.wappalyzer.categories = rules.categories;

        this.wappalyzer.parseJsPatterns();

        this.wappalyzer.driver.log = (message, source, type) => this.log(message, source, type);
        this.wappalyzer.driver.displayApps = (detected, meta, context) => this.displayApps(detected, meta, context);

        process.on('uncaughtException', e => this.wappalyzer.log(`Uncaught exception: ${e.message}`, 'driver', 'error'));
    }

    analyze() {
        const contentTypeWhiteList = ['application/json', 'application/xml'];

        this.time = {
            start: new Date().getTime(),
            last: new Date().getTime(),
        };

        this.headers = this.getHeaders(this.origPageHeaders);
        this.statusCode = this.getStatus(this.origPageHeaders);
        this.cookies = this.getCookies(this.headers);
        this.contentType = this.headers['content-type'] ? this.headers['content-type'].shift() : null;

        let type = this.contentType ? this.contentType.split(';').shift() : '';
        if (!type || contentTypeWhiteList.indexOf(type) == 0 || type.indexOf('text/') == 0) {
            this.html = this.getHtml(this.origPageContent, this.options.htmlMaxCols, this.options.htmlMaxRows);
        }

        if (type && type.indexOf('text/html') == 0) {
            this.links = this.getLinks(this.origPageContent);
            this.scripts = this.getScripts(this.origPageContent);
        }

        return this.crawl(this.origPageUrl);
    }

    log(message, source, type) {
        if (this.options.debug) {
            console.log(`[wappalyzer ${type}]`, `[${source}]`, message);
        }

        this.emit('log', { message, source, type });
    }

    displayApps(detected, meta, data) {
        this.meta = meta;

        Object.keys(detected).forEach((appName) => {
            const app = detected[appName];

            const categories = [];

            app.props.cats.forEach((id) => {
                categories.push({
                    id: id,
                    name: this.wappalyzer.categories[id].name
                });
            });

            if (!this.apps.some(detectedApp => detectedApp.name === app.name)) {
                this.apps.push({
                    name: app.name,
                    confidence: app.confidenceTotal.toString(),
                    version: app.version || null,
                    categories: categories
                });
            }
        });
    }

    fetch(pageUrl, index, depth) {
        if (this.analyzedPageUrls[pageUrl.href]) {
            return Promise.resolve();
        }

        this.analyzedPageUrls[pageUrl.href] = {
            status: this.statusCode,
        };

        const timerScope = {
            last: new Date().getTime(),
        };

        this.timer(`fetch; url: ${pageUrl.href}; depth: ${depth} delay: ${this.options.delay * index}ms`, timerScope);

        return new Promise(async(resolve, reject) => {
            await sleep(this.options.delay * index);

            this.visit(pageUrl, timerScope, resolve, reject);
        });
    }

    async visit(pageUrl, timerScope, resolve, reject) {
        const cookies = this.cookies;
        const headers = this.headers;
        const html = this.html;
        const js = this.js;
        const scripts = this.scripts;

        this.timer(`analyze start; url: ${pageUrl.href}`, timerScope);

        await this.wappalyzer.analyze(pageUrl, {
            cookies,
            headers,
            html,
            js,
            scripts,
        });

        this.timer(`analyze end; url: ${pageUrl.href}`, timerScope);

        const reducedLinks = [];

        return resolve(reducedLinks);
    }

    crawl(pageUrl, index = 1, depth = 1) {
        pageUrl.canonical = `${pageUrl.protocol}//${pageUrl.host}${pageUrl.pathname}`;

        return new Promise(async(resolve) => {
            try {
                await this.fetch(pageUrl, index, depth);
            } catch (error) {
                const type = error.message && errorTypes[error.message] ? error.message : 'UNKNOWN_ERROR';
                const message = error.message && errorTypes[error.message] ? errorTypes[error.message] : 'Unknown error';

                this.analyzedPageUrls[pageUrl.href].error = {
                    type,
                    message,
                };

                this.wappalyzer.log(`${message}; url: ${pageUrl.href}`, 'driver', 'error');
            }

            return resolve({
                applications: this.apps
            });
        });
    }

    timer(message, scope) {
        const time = new Date().getTime();
        const sinceStart = `${Math.round((time - this.time.start) / 10) / 100}s`;
        const sinceLast = `${Math.round((time - scope.last) / 10) / 100}s`;

        this.wappalyzer.log(`[timer] ${message}; lapsed: ${sinceLast} / ${sinceStart}`, 'driver');

        scope.last = time;
    }

    emit(event, params) {
        if (this.listeners[event]) {
            this.listeners[event].forEach(listener => listener(params));
        }
    }

    getStatus(origHeaders) {
        if (!origHeaders || origHeaders == null) return 0;

        let match = origHeaders.match(/^HTTP\/\d+\.\d+ (\d{3}) /);
        if (!match) return 0;

        return parseInt(match[1]);
    }

    decodeData(encoded_data) {
        const data = '';

        if (encoded_data == null || !encoded_data) return data;
        return new Buffer(encoded_data, 'base64').toString();
    }

    getHeaders(raw_headers) {
        const headers = {};

        if (raw_headers == null || !raw_headers) return headers;

        let decoded_headers = raw_headers.split('\r\n');
        decoded_headers.forEach((line) => {
            let pos = line.indexOf(':');
            if (pos > 0) {
                let headerName = line.substring(0, pos).trim().toLowerCase();

                if (headerName in headers) {
                    headers[headerName].push(line.substring(pos + 1).trim());
                } else {
                    headers[headerName] = [line.substring(pos + 1).trim()];
                }
            }
        });

        return headers;
    }

    getHtml(origHtml, maxCols, maxRows) {
        return processHtml(origHtml, maxCols, maxRows);
    }

    getScripts(html) {
        const scripts = [];
        if (!html || html == null) return scripts;

        let data = html;
        do {
            let script = data.match(/<script[^>]+?src=['"]*?([^'"]+)['"]*?/);
            if (script == null) break;

            scripts.push(script[1]);
            data = data.substring(script['index'] + script[0].length);
        } while (true);

        return scripts;
    }

    getLinks(html) {
        const links = [];
        if (!html || html == null) return links;

        let data = html;
        do {
            let link = data.match(/<(?:a|iframe)[^>]+?href=['"]*?([^'"]+)['"]*?/);
            if (link == null) break;

            links.push(link[1]);
            data = data.substring(link['index'] + link[0].length);
        } while (true);

        return links;
    }

    getCookies(headers) {
        const cookies = [];
        if (!headers || !('set-cookie' in headers)) return cookies;

        headers['set-cookie'].forEach((line) => {
            let parts = line.split(';');
            let name = '',
                value = '',
                domain = '',
                path = '';

            parts.forEach((part) => {
                let pos = part.indexOf('=');

                if (pos > 0) {
                    let lName = part.substring(0, pos);
                    let lValue = part.substring(pos + 1);

                    // 考虑 domain 和 path 在指纹识别中没有用，所以没有提取
                    if (!(lName.toLowerCase() in ['path', 'domain'])) {
                        cookies.push({
                            name: encodeURIComponent(lName),
                            value: encodeURIComponent(lValue),
                            domain: '',
                            path: '/'
                        });
                    }
                }
            });
        });

        return cookies;
    }
}

module.exports = Driver;