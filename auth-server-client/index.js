const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
const axios = require('axios');
const { spawn } = require('child_process');

function loadConfig(configPath) {
     if (!configPath) {
          throw new Error('Configuration path must be provided explicitly.');
     }

     const filePath = path.resolve(configPath);
     let config = {};
     if (fs.existsSync(filePath)) {
          try {
               const fileContents = fs.readFileSync(filePath, 'utf8');
               config = yaml.load(fileContents) || {};
          } catch (e) {
               throw new Error(`Failed to load configuration file: ${e.message}`);
          }
     } else {
          throw new Error(`Configuration file does not exist at path: ${filePath}`);
     }

     return config;
}


class AuthServerClient {
     constructor(options = {}) {
          this.config = loadConfig(options.configPath); // Will now throw if not given
          this.baseUrl = options.baseUrl || this.config?.app?.baseUrl || 'http://localhost:4554/api';
          this.axios = axios.create({ baseURL: this.baseUrl });
     }
     async login({ usernameOrEmail, password, twoFactorCode }) {
          const res = await this.axios.post('/auth/signin', { usernameOrEmail, password, twoFactorCode });
          return res.data;
     }
     async register({ username, email, password, firstName, lastName, roles }) {
          const res = await this.axios.post('/auth/signup', { username, email, password, firstName, lastName, roles });
          return res.data;
     }
     async refreshToken({ refreshToken }) {
          const res = await this.axios.post('/auth/refreshtoken', { refreshToken });
          return res.data;
     }
     async logout({ accessToken }) {
          const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
          const res = await this.axios.post('/auth/signout', {}, { headers });
          return res.data;
     }
     async verifyEmail({ token }) {
          const res = await this.axios.post('/auth/verify-email', null, { params: { token } });
          return res.data;
     }
     async resendVerification({ email }) {
          const res = await this.axios.post('/auth/resend-verification', null, { params: { email } });
          return res.data;
     }
     async forgotPassword({ email }) {
          const res = await this.axios.post('/auth/forgot-password', { email });
          return res.data;
     }
     async resetPassword({ token, newPassword }) {
          const res = await this.axios.post('/auth/reset-password', { token, newPassword });
          return res.data;
     }
     async setup2FA({ accessToken }) {
          const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
          const res = await this.axios.post('/auth/setup-2fa', {}, { headers });
          return res.data;
     }
     async verify2FA({ code }) {
          const res = await this.axios.post('/auth/verify-2fa', { code });
          return res.data;
     }
     async disable2FA({ code, accessToken }) {
          const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
          const res = await this.axios.post('/auth/disable-2fa', { code }, { headers });
          return res.data;
     }
     async getAdminDashboard({ accessToken }) {
          const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
          const res = await this.axios.get('/admin/dashboard', { headers });
          return res.data;
     }
     async getAllUsers({ accessToken }) {
          const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
          const res = await this.axios.get('/admin/users', { headers });
          return res.data;
     }
     async getRecentUsers({ accessToken, limit = 10 }) {
          const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
          const res = await this.axios.get('/admin/users/recent', { headers, params: { limit } });
          return res.data;
     }
     async enableUser({ accessToken, userId }) {
          const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
          const res = await this.axios.put(`/admin/users/${userId}/enable`, {}, { headers });
          return res.data;
     }
     async disableUser({ accessToken, userId }) {
          const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
          const res = await this.axios.put(`/admin/users/${userId}/disable`, {}, { headers });
          return res.data;
     }
     async deleteUser({ accessToken, userId }) {
          const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
          const res = await this.axios.delete(`/admin/users/${userId}`, { headers });
          return res.data;
     }
     async resetUser2FA({ accessToken, userId }) {
          const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
          const res = await this.axios.post(`/admin/users/${userId}/reset-2fa`, {}, { headers });
          return res.data;
     }
     async systemCleanup({ accessToken }) {
          const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
          const res = await this.axios.post('/admin/system/cleanup', {}, { headers });
          return res.data;
     }
     async getAllConfigurations({ accessToken }) {
          const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
          const res = await this.axios.get('/admin/config/all', { headers });
          return res.data;
     }
     async getConfigurationsByCategory({ accessToken, category }) {
          const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
          const res = await this.axios.get(`/admin/config/category/${category}`, { headers });
          return res.data;
     }
     async getEditableConfigurations({ accessToken }) {
          const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
          const res = await this.axios.get('/admin/config/editable', { headers });
          return res.data;
     }
     async getConfigurationByKey({ accessToken, key }) {
          const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
          const res = await this.axios.get(`/admin/config/${key}`, { headers });
          return res.data;
     }
     async createConfiguration({ accessToken, config }) {
          const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
          const res = await this.axios.post('/admin/config', config, { headers });
          return res.data;
     }
     async updateConfiguration({ accessToken, key, config }) {
          const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
          const res = await this.axios.put(`/admin/config/${key}`, config, { headers });
          return res.data;
     }
     async deleteConfiguration({ accessToken, key }) {
          const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
          const res = await this.axios.delete(`/admin/config/${key}`, { headers });
          return res.data;
     }
     async resetToDefaults({ accessToken }) {
          const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
          const res = await this.axios.post('/admin/config/reset-defaults', {}, { headers });
          return res.data;
     }
     async initializeDefaults({ accessToken }) {
          const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
          const res = await this.axios.post('/admin/config/initialize', {}, { headers });
          return res.data;
     }
     async reloadConfig({ accessToken }) {
          const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
          const res = await this.axios.post('/admin/system/reload-config', {}, { headers });
          return res.data;
     }
     async getSystemHealth({ accessToken }) {
          const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
          const res = await this.axios.get('/admin/system/health', { headers });
          return res.data;
     }
     async forceGC({ accessToken }) {
          const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
          const res = await this.axios.post('/admin/system/gc', {}, { headers });
          return res.data;
     }
     async getCustomConfigSummary({ accessToken }) {
          const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
          const res = await this.axios.get('/admin/custom-config/summary', { headers });
          return res.data;
     }
     async validateCustomConfig({ accessToken }) {
          const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
          const res = await this.axios.get('/admin/custom-config/validate', { headers });
          return res.data;
     }
     async getCustomConfigGuide({ accessToken }) {
          const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
          const res = await this.axios.get('/admin/custom-config/guide', { headers });
          return res.data;
     }
     async getEnvironmentRecommendations({ accessToken }) {
          const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
          const res = await this.axios.get('/admin/custom-config/recommendations', { headers });
          return res.data;
     }
     async getConfigFileStatus({ accessToken }) {
          const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
          const res = await this.axios.get('/admin/custom-config/file-status', { headers });
          return res.data;
     }
     async testAll() {
          const res = await this.axios.get('/test/all');
          return res.data;
     }
     async testUser({ accessToken }) {
          const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
          const res = await this.axios.get('/test/user', { headers });
          return res.data;
     }
     async testMod({ accessToken }) {
          const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
          const res = await this.axios.get('/test/mod', { headers });
          return res.data;
     }
     async testAdmin({ accessToken }) {
          const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
          const res = await this.axios.get('/test/admin', { headers });
          return res.data;
     }
     async health() {
          const res = await this.axios.get('/health');
          return res.data;
     }
}

class AuthWrapper {
     constructor(options = {}) {
          this.port = options.port || 4554;
          this.jarPath = options.jarPath || require('path').join(__dirname, 'target', 'authentication-server-1.0.0.jar');
          this.configPath = options.configPath;
          this.serverProcess = null;
          this.baseUrl = options.baseUrl || `http://localhost:${this.port}/api`;
          this.client = new AuthServerClient({ baseUrl: this.baseUrl, configPath: this.configPath });
     }
     startServer(onReady) {
          if (this.serverProcess) {
               return;
          }
          const javaArgs = ['-jar', this.jarPath];
          if (this.configPath) {
               javaArgs.push(`--spring.config.location=${this.configPath}`);
          }
          // Do NOT print Java logs to Node.js console, but print errors for debugging
          this.serverProcess = spawn('java', javaArgs, {
               cwd: require('path').dirname(this.jarPath),
               stdio: ['ignore', 'ignore', 'pipe'] // Only capture stderr
          });
          this.serverProcess.stderr.on('data', (data) => {
               console.error(`Java error: ${data}`);
          });
          // Print 'Running Auth app...' exactly after 10 seconds
          setTimeout(() => {
               console.log(`Running Auth app on port ${this.port}...`);
          }, 10000);
          let notified = false;
          let healthReady = false;
          const minTime = 5000;
          const startTime = Date.now();
          const checkReady = async () => {
               try {
                    await this.client.health();
                    healthReady = true;
                    const elapsed = Date.now() - startTime;
                    if (!notified && elapsed >= minTime) {
                         notified = true;
                         console.log(`Auth app is running on port ${this.port}`);
                         if (onReady) onReady();
                    } else if (!notified) {
                         setTimeout(checkReady, minTime - elapsed);
                    }
               } catch (e) {
                    setTimeout(checkReady, 500);
               }
          };
          checkReady();
          setTimeout(() => {
               if (healthReady && !notified) {
                    notified = true;
                    console.log(`Auth app is running on port ${this.port}`);
                    if (onReady) onReady();
               }
          }, minTime);
          this.serverProcess.on('close', (code) => {
               this.serverProcess = null;
          });
     }
     stopServer() {
          if (this.serverProcess) {
               this.serverProcess.kill();
               this.serverProcess = null;
          }
     }
     async login({ usernameOrEmail, password }) {
          return this.client.login({ usernameOrEmail, password });
     }
     startServerAsync() {
          return new Promise((resolve) => {
               this.startServer(resolve);
          });
     }
}

module.exports = { AuthWrapper, AuthServerClient, loadConfig }; 