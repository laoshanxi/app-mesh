// appmesh_client.js

const axios = require("axios");
const https = require("https");
const { parse, toSeconds } = require("iso8601-duration");

const DEFAULT_TOKEN_EXPIRE_SECONDS = "P1W"; // default 7 day(s)

class AppMeshClient {
    constructor(baseURL, verifySSL = false) {
        this.baseURL = baseURL;
        this.token = null;
        this.delegateHost = null;
        this.client = axios.create({
            baseURL,
            httpsAgent: new https.Agent({
                rejectUnauthorized: verifySSL,
            }),
        });
    }

    // Login
    async login(
        username,
        password,
        totp = null,
        expireSeconds = toSeconds(DEFAULT_TOKEN_EXPIRE_SECONDS)
    ) {
        const auth = Buffer.from(`${username}:${password}`).toString("base64");
        const headers = { Authorization: `Basic ${auth}` };
        if (totp) {
            headers["Totp"] = totp;
        }
        if (expireSeconds) {
            headers["Expire-Seconds"] = expireSeconds;
        }

        try {
            this.token = null;
            const response = await this.client.post("/appmesh/login", null, {
                headers,
            });
            if (response.status !== 200) {
                throw new Error(response.data);
            }
            this.token = response.data["Access-Token"];
            return this.token;
        } catch (error) {
            throw this._handleError(error);
        }
    }

    async authentication(token, permission = null) {
        try {
            const headers = this._createHeaders();
            if (permission) {
                headers["Auth-Permission"] = permission;
            }
            const response = await this.client.post("/appmesh/auth", null, {
                headers: headers,
            });

            if (response.status === 200) {
                this.token = token;
                return true;
            }
            return false;
        } catch (error) {
            throw this._handleError(error);
        }
    }

    async logout() {
        try {
            const headers = this._createHeaders();
            const response = await this.client.post("/appmesh/self/logoff", null, {
                headers: headers,
            });
            this.token = null;
            return response.status === 200;
        } catch (error) {
            throw this._handleError(error);
        }
    }

    async renew(expireSeconds = toSeconds(DEFAULT_TOKEN_EXPIRE_SECONDS)) {
        const headers = this._createHeaders();
        if (expireSeconds) {
            headers["Expire-Seconds"] = expireSeconds;
        }

        try {
            const response = await this.client.post("/appmesh/token/renew", null, {
                headers: headers,
            });
            if (response.status === 200) {
                this.token = response.data["Access-Token"];
                return this.token;
            }
            throw new Error(response.data);
        } catch (error) {
            throw this._handleError(error);
        }
    }

    // Applications
    async app_view_all() {
        try {
            const headers = this._createHeaders();
            const response = await this.client.get("/appmesh/applications", {
                headers: headers,
            });
            return response.data;
        } catch (error) {
            throw this._handleError(error);
        }
    }

    async app_view(name) {
        try {
            const headers = this._createHeaders();
            const response = await this.client.get(`/appmesh/app/${name}`, {
                headers: headers,
            });
            return response.data;
        } catch (error) {
            throw this._handleError(error);
        }
    }

    // Common function to create headers
    _createHeaders() {
        const headers = {
            Authorization: `Bearer ${this.token}`,
            "User-Agent": "APPMESH_JS_SDK",
        };
        if (this.delegateHost) {
            if (this.delegateHost.includes(":")) {
                headers["X-Target-Host"] = this.delegateHost;
            } else {
                const parsedUrl = new URL(this.baseURL);
                headers["X-Target-Host"] = `${this.delegateHost}:${parsedUrl.port}`;
            }
        }
        return headers;
    }

    // Error handling
    _handleError(error) {
        if (error.response) {
            const { status, data } = error.response;
            return new Error(`HTTP ${status}: ${JSON.stringify(data)}`);
        }
        return error;
    }
}

module.exports = AppMeshClient;
