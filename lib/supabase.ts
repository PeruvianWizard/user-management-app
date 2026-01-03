 import { createClient } from "@supabase/supabase-js";
 import AsyncStorage from "@react-native-async-storage/async-storage";
 import * as SecureStore from 'expo-secure-store';
 import * as aesjs from 'aes-js';
 import 'react-native-get-random-values';

 // Because Expo's SecureStore does not support values larger than 2048 bytes,
 // the AES-256 key is generated and stored in SecureStore, and it is then used
 // encrypt/decrypt the values stored in AsyncStorage
 class LargeSecureStore {
    private async _encrypt(key: string, value: string) {
        // crypto.getRandomValues() returns a cryptographically strong random values
        // The array passed as parameter to this function is filled with random numbers
        const encryptionKey = crypto.getRandomValues(new Uint8Array(256 / 8));

        // Use CTR encryption method
        const cipher = new aesjs.ModeOfOperation.ctr(encryptionKey, new aesjs.Counter(1));
        const encryptedBytes = cipher.encrypt(aesjs.utils.utf8.toBytes(value));

        // Encryption Key stored in SecureStore
        await SecureStore.setItemAsync(key, aesjs.utils.hex.fromBytes(encryptionKey));

        return aesjs.utils.hex.fromBytes(encryptedBytes);
    }

    private async _decrypt(key: string, value: string) {
        const encryptionKeyHex = await SecureStore.getItemAsync(key);
        if (!encryptionKeyHex) {
            return encryptionKeyHex;
        }

        const cipher = new aesjs.ModeOfOperation.ctr(aesjs.utils.hex.toBytes(encryptionKeyHex), new aesjs.Counter(1));
        const decryptedBytes = cipher.decrypt(aesjs.utils.hex.toBytes(value));

        return aesjs.utils.utf8.fromBytes(decryptedBytes);
    }

    async getItem(key: string) {
        const encrypted = await AsyncStorage.getItem(key);
        if (!encrypted)  { return encrypted; }

        return await this._decrypt(key, encrypted);
    }

    async removeItem(key: string) {
        await AsyncStorage.removeItem(key);
        await SecureStore.deleteItemAsync(key);
    }

    async setItem(key: string, value: string) {
        const encrypted = await this._encrypt(key, value);

        await AsyncStorage.setItem(key, encrypted);
    }
 }

const supabaseUrl = process.env.EXPO_PUBLIC_SUPABASE_URL;
const supabasePublishableKey = process.env.EXPO_PUBLIC_SUPABASE_KEY;

export const supabase = createClient(supabaseUrl, supabasePublishableKey, {
    auth: {
        storage: new LargeSecureStore(),
        autoRefreshToken: true,
        persistSession: true,
        detectSessionInUrl: false,
    },
});