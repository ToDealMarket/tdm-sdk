type KeytarModule = {
  getPassword: (service: string, account: string) => Promise<string | null>;
  setPassword: (service: string, account: string, password: string) => Promise<void>;
  deletePassword: (service: string, account: string) => Promise<boolean | void>;
};

export interface KeyringRef {
  service: string;
  account: string;
}

const KEYRING_SCHEME = 'os-keyring://';

let keytarPromise: Promise<KeytarModule> | null = null;

export function getKeyringPlatformHint(): string {
  if (typeof process === 'undefined') {
    return 'Ensure keytar is installed and the system keychain is unlocked.';
  }

  if (process.platform === 'darwin') {
    return 'On macOS, ensure keytar is installed and the login Keychain is unlocked.';
  }

  if (process.platform === 'linux') {
    return 'On Linux, ensure keytar is installed and a Secret Service backend such as gnome-keyring/libsecret is available.';
  }

  if (process.platform === 'win32') {
    return 'On Windows, ensure keytar is installed and Credential Manager is available.';
  }

  return 'Ensure keytar is installed and the system keychain is unlocked.';
}

function normalizeKeyringError(error: unknown): Error {
  const message = error instanceof Error ? error.message : String(error);
  return new Error(
    `OS keyring is unavailable. ${getKeyringPlatformHint()} (${message})`,
  );
}

async function loadKeytar(): Promise<KeytarModule> {
  if (keytarPromise) {
    return keytarPromise;
  }

  keytarPromise = (async () => {
    try {
      const module = await import('keytar');
      const keytar = (module.default ?? module) as KeytarModule;
      if (
        !keytar ||
        typeof keytar.getPassword !== 'function' ||
        typeof keytar.setPassword !== 'function' ||
        typeof keytar.deletePassword !== 'function'
      ) {
        throw new Error('Invalid keytar module shape');
      }
      return keytar;
    } catch (error) {
      throw normalizeKeyringError(error);
    }
  })();

  keytarPromise.catch(() => {
    keytarPromise = null;
  });

  return keytarPromise;
}

function assertPart(label: string, value: string): string {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error(`Keyring ${label} must be non-empty`);
  }
  if (trimmed.includes('://') || trimmed.includes('\n')) {
    throw new Error(`Keyring ${label} contains invalid characters`);
  }
  return trimmed;
}

export function buildKeyringRef(service: string, account: string): string {
  const normalizedService = assertPart('service', service);
  const normalizedAccount = assertPart('account', account);
  return `${KEYRING_SCHEME}${normalizedService}/${normalizedAccount}`;
}

export function parseKeyringRef(ref: string): KeyringRef {
  if (!ref.startsWith(KEYRING_SCHEME)) {
    throw new Error(`Invalid keyring ref "${ref}". Expected ${KEYRING_SCHEME}service/account`);
  }
  const raw = ref.slice(KEYRING_SCHEME.length);
  const [service, ...accountParts] = raw.split('/');
  if (!service || accountParts.length === 0) {
    throw new Error(`Invalid keyring ref "${ref}". Expected ${KEYRING_SCHEME}service/account`);
  }
  const account = accountParts.join('/').trim();
  if (!account) {
    throw new Error(`Invalid keyring ref "${ref}". Account must be non-empty`);
  }
  return {
    service: assertPart('service', service),
    account: assertPart('account', account),
  };
}

export async function assertKeyringAvailable(): Promise<void> {
  await loadKeytar();
}

export async function getKeyringPassword(service: string, account: string): Promise<string | null> {
  const keytar = await loadKeytar();
  try {
    return await keytar.getPassword(service, account);
  } catch (error) {
    throw normalizeKeyringError(error);
  }
}

export async function setKeyringPassword(
  service: string,
  account: string,
  password: string,
): Promise<void> {
  const keytar = await loadKeytar();
  try {
    await keytar.setPassword(service, account, password);
  } catch (error) {
    throw normalizeKeyringError(error);
  }
}

export async function deleteKeyringPassword(
  service: string,
  account: string,
): Promise<void> {
  const keytar = await loadKeytar();
  try {
    await keytar.deletePassword(service, account);
  } catch (error) {
    throw normalizeKeyringError(error);
  }
}

export async function getKeyringSecret(ref: string): Promise<string | null> {
  const { service, account } = parseKeyringRef(ref);
  return getKeyringPassword(service, account);
}

export async function setKeyringSecret(ref: string, secret: string): Promise<void> {
  const { service, account } = parseKeyringRef(ref);
  await setKeyringPassword(service, account, secret);
}

export async function deleteKeyringSecret(ref: string): Promise<void> {
  const { service, account } = parseKeyringRef(ref);
  await deleteKeyringPassword(service, account);
}
