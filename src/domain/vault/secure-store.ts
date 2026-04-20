import {
  assertKeyringAvailable,
  deleteKeyringPassword,
  getKeyringPassword,
  setKeyringPassword,
} from './keyring.js';

export interface SecureStoreMetadata {
  backend: 'keyring' | 'encrypted-file';
}

export class SecureSecretStore {
  private readonly serviceName: string;
  private readonly namespace: string;

  constructor(options: { serviceName?: string; namespace?: string } = {}) {
    this.serviceName = options.serviceName ?? 'tdm-sdk';
    this.namespace = options.namespace ?? 'default';
  }

  async describeBackend(): Promise<SecureStoreMetadata> {
    await assertKeyringAvailable();
    return { backend: 'keyring' };
  }

  async getSecret(key: string): Promise<string | null> {
    const qualifiedKey = this.qualifyKey(key);
    return getKeyringPassword(this.serviceName, qualifiedKey);
  }

  async setSecret(key: string, value: string): Promise<void> {
    const qualifiedKey = this.qualifyKey(key);
    await setKeyringPassword(this.serviceName, qualifiedKey, value);
  }

  async deleteSecret(key: string): Promise<void> {
    const qualifiedKey = this.qualifyKey(key);
    await deleteKeyringPassword(this.serviceName, qualifiedKey);
  }

  private qualifyKey(key: string): string {
    return `${this.namespace}:${key}`;
  }
}
