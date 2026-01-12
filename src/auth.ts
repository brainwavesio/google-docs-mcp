// src/auth.ts
import { google } from 'googleapis';
import { OAuth2Client } from 'google-auth-library';
import { JWT } from 'google-auth-library';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as readline from 'readline/promises';
import { fileURLToPath } from 'url';

// --- Calculate paths relative to this script file (ESM way) ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRootDir = path.resolve(__dirname, '..');

const TOKEN_PATH = path.join(projectRootDir, 'token.json');
const CREDENTIALS_PATH = path.join(projectRootDir, 'credentials.json');
// --- End of path calculation ---

const SCOPES = [
  'https://www.googleapis.com/auth/documents',
  'https://www.googleapis.com/auth/drive',
  'https://www.googleapis.com/auth/spreadsheets'
];

// --- Environment variable authentication ---
// Supports OAuth credentials via env vars for containerized/npx usage:
// - GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REFRESH_TOKEN
// - Or GOOGLE_CREDENTIALS_JSON (full credentials.json content as string)
function hasEnvCredentials(): boolean {
  return !!(
    (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && process.env.GOOGLE_REFRESH_TOKEN) ||
    process.env.GOOGLE_CREDENTIALS_JSON
  );
}

async function authorizeWithEnvCredentials(): Promise<OAuth2Client> {
  let clientId: string;
  let clientSecret: string;
  let refreshToken: string | undefined;

  if (process.env.GOOGLE_CREDENTIALS_JSON) {
    // Parse the full credentials.json from env var
    const keys = JSON.parse(process.env.GOOGLE_CREDENTIALS_JSON);
    const key = keys.installed || keys.web;
    if (!key) {
      throw new Error('GOOGLE_CREDENTIALS_JSON must contain "installed" or "web" key');
    }
    clientId = key.client_id;
    clientSecret = key.client_secret;
    refreshToken = process.env.GOOGLE_REFRESH_TOKEN;
  } else {
    clientId = process.env.GOOGLE_CLIENT_ID!;
    clientSecret = process.env.GOOGLE_CLIENT_SECRET!;
    refreshToken = process.env.GOOGLE_REFRESH_TOKEN;
  }

  const client = new google.auth.OAuth2(clientId, clientSecret);

  if (refreshToken) {
    client.setCredentials({ refresh_token: refreshToken });
    console.error('Using OAuth credentials from environment variables.');
    return client;
  }

  // No refresh token - need to do interactive auth flow
  console.error('No GOOGLE_REFRESH_TOKEN found. Starting interactive OAuth flow...');
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  const authorizeUrl = client.generateAuthUrl({
    access_type: 'offline',
    scope: SCOPES.join(' '),
  });

  console.error('Authorize this app by visiting this url:', authorizeUrl);
  const code = await rl.question('Enter the code from that page here: ');
  rl.close();

  const { tokens } = await client.getToken(code);
  client.setCredentials(tokens);

  if (tokens.refresh_token) {
    console.error('\n=== SAVE THIS REFRESH TOKEN ===');
    console.error('Add this to your environment:');
    console.error(`GOOGLE_REFRESH_TOKEN=${tokens.refresh_token}`);
    console.error('===============================\n');
  }

  console.error('Authentication successful!');
  return client;
}
// --- End of environment variable authentication ---

// --- Service Account Authentication ---
async function authorizeWithServiceAccount(): Promise<JWT> {
  const serviceAccountPath = process.env.SERVICE_ACCOUNT_PATH!;
  const impersonateUser = process.env.GOOGLE_IMPERSONATE_USER;
  try {
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
  } catch (error: any) {
    if (error.code === 'ENOENT') {
      console.error(`FATAL: Service account key file not found at path: ${serviceAccountPath}`);
      throw new Error(`Service account key file not found. Please check the path in SERVICE_ACCOUNT_PATH.`);
    }
    console.error('FATAL: Error loading or authorizing the service account key:', error.message);
    throw new Error('Failed to authorize using the service account. Ensure the key file is valid and the path is correct.');
  }
}
// --- End of Service Account Authentication ---

// --- File-based OAuth (original behavior) ---
async function loadSavedCredentialsIfExist(): Promise<OAuth2Client | null> {
  try {
    const content = await fs.readFile(TOKEN_PATH);
    const credentials = JSON.parse(content.toString());
    const { client_secret, client_id, redirect_uris } = await loadClientSecrets();
    const client = new google.auth.OAuth2(client_id, client_secret, redirect_uris?.[0]);
    client.setCredentials(credentials);
    return client;
  } catch (err) {
    return null;
  }
}

async function loadClientSecrets() {
  const content = await fs.readFile(CREDENTIALS_PATH);
  const keys = JSON.parse(content.toString());
  const key = keys.installed || keys.web;
  if (!key) throw new Error("Could not find client secrets in credentials.json.");
  return {
    client_id: key.client_id,
    client_secret: key.client_secret,
    redirect_uris: key.redirect_uris || ['http://localhost:3000/'],
    client_type: keys.web ? 'web' : 'installed'
  };
}

async function saveCredentials(client: OAuth2Client): Promise<void> {
  const { client_secret, client_id } = await loadClientSecrets();
  const payload = JSON.stringify({
    type: 'authorized_user',
    client_id: client_id,
    client_secret: client_secret,
    refresh_token: client.credentials.refresh_token,
  });
  await fs.writeFile(TOKEN_PATH, payload);
  console.error('Token stored to', TOKEN_PATH);
}

async function authenticate(): Promise<OAuth2Client> {
  const { client_secret, client_id, redirect_uris, client_type } = await loadClientSecrets();
  const redirectUri = client_type === 'web' ? redirect_uris[0] : 'urn:ietf:wg:oauth:2.0:oob';
  console.error(`DEBUG: Using redirect URI: ${redirectUri}`);
  console.error(`DEBUG: Client type: ${client_type}`);
  const oAuth2Client = new google.auth.OAuth2(client_id, client_secret, redirectUri);

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  const authorizeUrl = oAuth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: SCOPES.join(' '),
  });

  console.error('DEBUG: Generated auth URL:', authorizeUrl);
  console.error('Authorize this app by visiting this url:', authorizeUrl);
  const code = await rl.question('Enter the code from that page here: ');
  rl.close();

  try {
    const { tokens } = await oAuth2Client.getToken(code);
    oAuth2Client.setCredentials(tokens);
    if (tokens.refresh_token) {
      await saveCredentials(oAuth2Client);
    } else {
      console.error("Did not receive refresh token. Token might expire.");
    }
    console.error('Authentication successful!');
    return oAuth2Client;
  } catch (err) {
    console.error('Error retrieving access token', err);
    throw new Error('Authentication failed');
  }
}
// --- End of file-based OAuth ---

// --- Main exported function ---
// Priority order:
// 1. Service account (SERVICE_ACCOUNT_PATH)
// 2. Environment variables (GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET + GOOGLE_REFRESH_TOKEN, or GOOGLE_CREDENTIALS_JSON)
// 3. File-based OAuth (credentials.json + token.json)
export async function authorize(): Promise<OAuth2Client | JWT> {
  // 1. Check for service account
  if (process.env.SERVICE_ACCOUNT_PATH) {
    console.error('Service account path detected. Attempting service account authentication...');
    return authorizeWithServiceAccount();
  }

  // 2. Check for env var credentials
  if (hasEnvCredentials()) {
    console.error('Environment variable credentials detected. Using env-based authentication...');
    return authorizeWithEnvCredentials();
  }

  // 3. Fall back to file-based OAuth
  console.error('Using file-based OAuth flow...');
  let client = await loadSavedCredentialsIfExist();
  if (client) {
    console.error('Using saved credentials.');
    return client;
  }
  console.error('Starting authentication flow...');
  client = await authenticate();
  return client;
}
