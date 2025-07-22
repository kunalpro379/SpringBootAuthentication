const express = require('express');
const path = require('path');
const { AuthWrapper } = require('auth-server-client'); // Ensure this is the right module

const resolvedConfigPath = path.resolve(__dirname, 'app.config.yml');

const wrapper = new AuthWrapper({
     port: 4554,
     configPath: resolvedConfigPath
});

const app = express();
const port = 3001;

app.use(express.json());

app.post('/api/login', async (req, res) => {
     try {
          const { usernameOrEmail, password } = req.body;
          const result = await wrapper.login({ usernameOrEmail, password });
          res.json(result);
     } catch (err) {
          res.status(err.response?.status || 500).json(err.response?.data || { error: err.message });
     }
});

app.get('/abc/xyz/health', (req, res) => {
     res.json({ status: 'ok' });
});

(async () => {
     try {
          wrapper.startServerAsync();
          app.listen(port, () => {
               console.log(`✅ Express server running at http://localhost:${port}`);
          });
     } catch (err) {
          console.error('❌ Failed to start servers:', err);
          process.exit(1);
     }
})();
