// src/auth.ts
import { google } from 'googleapis';
import { OAuth2Client } from 'google-auth-library';
import { JWT } from 'google-auth-library';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as http from 'http';
import * as os from 'os';
import { fileURLToPath } from 'url';
import open from 'open';

// --- Config directory for persistent token storage ---
const CONFIG_DIR = path.join(os.homedir(), '.config', 'google-docs-mcp');
const TOKEN_PATH = path.join(CONFIG_DIR, 'token.json');

// --- Legacy paths (for backwards compatibility) ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRootDir = path.resolve(__dirname, '..');
const LEGACY_TOKEN_PATH = path.join(projectRootDir, 'token.json');
const LEGACY_CREDENTIALS_PATH = path.join(projectRootDir, 'credentials.json');

const SCOPES = [
  'https://www.googleapis.com/auth/documents',
  'https://www.googleapis.com/auth/drive',
  'https://www.googleapis.com/auth/spreadsheets'
];

// --- Ensure config directory exists ---
async function ensureConfigDir(): Promise<void> {
  try {
    await fs.mkdir(CONFIG_DIR, { recursive: true });
  } catch (err) {
    // Directory might already exist
  }
}

// --- Save token to config directory ---
async function saveToken(credentials: {
  client_id: string;
  client_secret: string;
  refresh_token: string;
}): Promise<void> {
  await ensureConfigDir();
  const payload = JSON.stringify({
    type: 'authorized_user',
    client_id: credentials.client_id,
    client_secret: credentials.client_secret,
    refresh_token: credentials.refresh_token,
  }, null, 2);
  await fs.writeFile(TOKEN_PATH, payload);
  console.error(`Token saved to ${TOKEN_PATH}`);
}

// --- Load token from config directory or legacy location ---
async function loadSavedToken(): Promise<{
  client_id: string;
  client_secret: string;
  refresh_token: string;
} | null> {
  // Try new config location first
  try {
    const content = await fs.readFile(TOKEN_PATH, 'utf8');
    const token = JSON.parse(content);
    if (token.refresh_token) {
      return token;
    }
  } catch (err) {
    // Not found in config dir, try legacy location
  }

  // Try legacy token.json in project root
  try {
    const content = await fs.readFile(LEGACY_TOKEN_PATH, 'utf8');
    const token = JSON.parse(content);
    if (token.refresh_token) {
      return token;
    }
  } catch (err) {
    // Not found
  }

  return null;
}

// --- Browser-based OAuth flow ---
async function authenticateWithBrowser(
  clientId: string,
  clientSecret: string
): Promise<OAuth2Client> {
  return new Promise((resolve, reject) => {
    // Find an available port
    const server = http.createServer();

    server.listen(0, '127.0.0.1', async () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        reject(new Error('Failed to start local server'));
        return;
      }

      const port = address.port;
      const redirectUri = `http://127.0.0.1:${port}/callback`;

      const client = new google.auth.OAuth2(clientId, clientSecret, redirectUri);

      const authorizeUrl = client.generateAuthUrl({
        access_type: 'offline',
        scope: SCOPES,
        prompt: 'consent', // Force consent to ensure we get a refresh token
      });

      console.error('\n========================================');
      console.error('Opening browser for Google authorization...');
      console.error('If the browser does not open, visit this URL:');
      console.error(authorizeUrl);
      console.error('========================================\n');

      // Handle the OAuth callback
      server.on('request', async (req, res) => {
        if (!req.url?.startsWith('/callback')) {
          res.writeHead(404);
          res.end('Not found');
          return;
        }

        const url = new URL(req.url, `http://127.0.0.1:${port}`);
        const code = url.searchParams.get('code');
        const error = url.searchParams.get('error');

        if (error) {
          res.writeHead(400, { 'Content-Type': 'text/html' });
          res.end(`
            <html>
              <body style="font-family: system-ui; padding: 40px; text-align: center;">
                <h1>Authorization Failed</h1>
                <p>Error: ${error}</p>
                <p>You can close this window.</p>
              </body>
            </html>
          `);
          server.close();
          reject(new Error(`Authorization failed: ${error}`));
          return;
        }

        if (!code) {
          res.writeHead(400, { 'Content-Type': 'text/html' });
          res.end(`
            <html>
              <body style="font-family: system-ui; padding: 40px; text-align: center;">
                <h1>Authorization Failed</h1>
                <p>No authorization code received.</p>
                <p>You can close this window.</p>
              </body>
            </html>
          `);
          server.close();
          reject(new Error('No authorization code received'));
          return;
        }

        try {
          const { tokens } = await client.getToken(code);
          client.setCredentials(tokens);

          if (tokens.refresh_token) {
            await saveToken({
              client_id: clientId,
              client_secret: clientSecret,
              refresh_token: tokens.refresh_token,
            });
          }

          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(`
            <html>
              <body style="font-family: system-ui; padding: 40px; text-align: center;">
                <h1>Authorization Successful!</h1>
                <p>You can close this window and return to your application.</p>
                <script>window.close();</script>
              </body>
            </html>
          `);

          server.close();
          console.error('Authorization successful!');
          resolve(client);
        } catch (err) {
          res.writeHead(500, { 'Content-Type': 'text/html' });
          res.end(`
            <html>
              <body style="font-family: system-ui; padding: 40px; text-align: center;">
                <h1>Authorization Failed</h1>
                <p>Failed to exchange code for tokens.</p>
                <p>You can close this window.</p>
              </body>
            </html>
          `);
          server.close();
          reject(err);
        }
      });

      // Set a timeout for the auth flow
      const timeout = setTimeout(() => {
        server.close();
        reject(new Error('Authorization timed out after 5 minutes'));
      }, 5 * 60 * 1000);

      server.on('close', () => {
        clearTimeout(timeout);
      });

      // Open the browser
      try {
        await open(authorizeUrl);
      } catch (err) {
        console.error('Failed to open browser automatically.');
        console.error('Please open the URL above manually.');
      }
    });

    server.on('error', (err) => {
      reject(err);
    });
  });
}

// --- Get OAuth credentials from env vars or files ---
function getClientCredentials(): { clientId: string; clientSecret: string } | null {
  // Check environment variables first
  if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    return {
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    };
  }

  // Check for GOOGLE_CREDENTIALS_JSON env var
  if (process.env.GOOGLE_CREDENTIALS_JSON) {
    try {
      const keys = JSON.parse(process.env.GOOGLE_CREDENTIALS_JSON);
      const key = keys.installed || keys.web;
      if (key) {
        return {
          clientId: key.client_id,
          clientSecret: key.client_secret,
        };
      }
    } catch (err) {
      console.error('Failed to parse GOOGLE_CREDENTIALS_JSON');
    }
  }

  return null;
}

// --- Load credentials.json file (legacy support) ---
async function loadCredentialsFile(): Promise<{ clientId: string; clientSecret: string } | null> {
  try {
    const content = await fs.readFile(LEGACY_CREDENTIALS_PATH, 'utf8');
    const keys = JSON.parse(content);
    const key = keys.installed || keys.web;
    if (key) {
      return {
        clientId: key.client_id,
        clientSecret: key.client_secret,
      };
    }
  } catch (err) {
    // File not found or invalid
  }
  return null;
}

// --- Service Account Authentication ---
async function authorizeWithServiceAccount(): Promise<JWT> {
  const serviceAccountPath = process.env.SERVICE_ACCOUNT_PATH!;
  const impersonateUser = process.env.GOOGLE_IMPERSONATE_USER;

  const keyFileContent = await fs.readFile(serviceAccountPath, 'utf8');
  const serviceAccountKey = JSON.parse(keyFileContent);

  const auth = new JWT({
    email: serviceAccountKey.client_email,
    key: serviceAccountKey.private_key,
    scopes: SCOPES,
    subject: impersonateUser,
  });

  await auth.authorize();

  if (impersonateUser) {
    console.error(`Service Account authentication successful, impersonating: ${impersonateUser}`);
  } else {
    console.error('Service Account authentication successful!');
  }

  return auth;
}

// --- Main exported function ---
// Priority order:
// 1. Service account (SERVICE_ACCOUNT_PATH)
// 2. Saved token + env credentials
// 3. Env var refresh token (GOOGLE_REFRESH_TOKEN)
// 4. Browser-based OAuth flow
// 5. Legacy file-based credentials
export async function authorize(): Promise<OAuth2Client | JWT> {
  // 1. Check for service account
  if (process.env.SERVICE_ACCOUNT_PATH) {
    console.error('Service account path detected. Using service account authentication...');
    return authorizeWithServiceAccount();
  }

  // Get client credentials from env or files
  let credentials = getClientCredentials();

  // 2. Check for saved token
  const savedToken = await loadSavedToken();

  if (savedToken) {
    // Use saved token - prefer env credentials if available, otherwise use token's credentials
    const clientId = credentials?.clientId || savedToken.client_id;
    const clientSecret = credentials?.clientSecret || savedToken.client_secret;

    const client = new google.auth.OAuth2(clientId, clientSecret);
    client.setCredentials({ refresh_token: savedToken.refresh_token });
    console.error('Using saved credentials from ~/.config/google-docs-mcp/');
    return client;
  }

  // 3. Check for refresh token in env var
  if (credentials && process.env.GOOGLE_REFRESH_TOKEN) {
    const client = new google.auth.OAuth2(credentials.clientId, credentials.clientSecret);
    client.setCredentials({ refresh_token: process.env.GOOGLE_REFRESH_TOKEN });

    // Save this token for future use
    await saveToken({
      client_id: credentials.clientId,
      client_secret: credentials.clientSecret,
      refresh_token: process.env.GOOGLE_REFRESH_TOKEN,
    });

    console.error('Using refresh token from environment variable.');
    return client;
  }

  // 4. Try to load credentials from file if not in env
  if (!credentials) {
    credentials = await loadCredentialsFile();
  }

  // 5. If we have client credentials, do browser-based OAuth
  if (credentials) {
    console.error('No saved token found. Starting browser-based authentication...');
    return authenticateWithBrowser(credentials.clientId, credentials.clientSecret);
  }

  // No credentials available
  throw new Error(
    'No Google credentials found. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables, ' +
    'or place a credentials.json file in the project directory.'
  );
}
