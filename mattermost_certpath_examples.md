```markdown
# Mattermost React Native Network Client: `importClientP12` Function

The `@mattermost/react-native-network-client` library provides a function `importClientP12` to import client certificates in `.p12` format. This is typically used for mutual TLS authentication.

## Function Signature
```typescript
importClientP12(certPath: string, password: string): Promise<void>
```

## Parameters

### `certPath` (Android only)
- **Type:** `string`
- **Description:**
  - `certPath` is the **absolute path** to the `.p12` client certificate file on the Android device.
  - It must be accessible to the app (for example, in the app's assets, internal storage, or a path obtained via a file picker).
  - The path **cannot** be a relative path; Android requires a full filesystem path.

### `password`
- **Type:** `string`
- **Description:** The password protecting the `.p12` file.

## Example Usage

### Example 1: Using a certificate stored in the app's assets folder
```typescript
import {importClientP12} from '@mattermost/react-native-network-client';
import RNFS from 'react-native-fs';

async function importCert() {
    try {
        // Copy certificate from assets to internal storage
        const destPath = `${RNFS.DocumentDirectoryPath}/client_cert.p12`;
        await RNFS.copyFileAssets('client_cert.p12', destPath);

        // Import the certificate
        await importClientP12(destPath, 'your_password');
        console.log('Certificate imported successfully');
    } catch (error) {
        console.error('Error importing certificate:', error);
    }
}
```

### Example 2: Using a certificate selected via a file picker
```typescript
import DocumentPicker from 'react-native-document-picker';
import {importClientP12} from '@mattermost/react-native-network-client';

async function pickAndImportCert() {
    try {
        const res = await DocumentPicker.pickSingle({
            type: [DocumentPicker.types.allFiles],
        });

        console.log('Picked file:', res.uri);

        // Android: res.uri may be like content://...; use RNFS or a helper to resolve to actual path
        const actualPath = await resolveFilePath(res.uri);

        await importClientP12(actualPath, 'your_password');
        console.log('Certificate imported successfully');
    } catch (err) {
        if (DocumentPicker.isCancel(err)) {
            console.log('User cancelled the picker');
        } else {
            console.error('Error:', err);
        }
    }
}

// Helper to resolve Android content URI to filesystem path
async function resolveFilePath(uri: string): Promise<string> {
    // Implementation depends on library or custom native module
    return uri; // placeholder
}
```

## Notes
- On **iOS**, this parameter is ignored since `importClientP12` is Android-specific.
- Always ensure that the certificate file is stored in a location accessible by the app.
- Incorrect paths or inaccessible files will throw an error.

## References
- [Mattermost React Native Network Client GitHub](https://github.com/mattermost/react-native-network-client)
- [Android File System Access](https://reactnative.dev/docs/filesystem)

```
---------------------
```markdown
# Mattermost Mobile (Android) HTTPS Connection Without Client Certificate

In Mattermost Desktop, it is possible to send HTTPS requests to a server without providing a client certificate. While this may generate warnings or errors, the connection often succeeds because desktop environments trust system CA certificates.

However, on **Mattermost Mobile (Android)**, the behavior is stricter:

- Android enforces TLS/SSL certificate validation for all HTTPS requests.
- If the server uses a certificate not trusted by the Android system (e.g., self-signed or internal CA), requests will **fail** unless the client certificate or proper CA certificate is provided.
- Unlike desktop, there is no implicit trust for self-signed certificates unless explicitly configured.

## Options to Connect Without Client Certificate on Android

### 1. Use a Publicly Trusted Certificate
- Ensure the Mattermost server uses a certificate signed by a **public CA** trusted by Android devices.
- This eliminates the need for client-side certificates.
- Example: certificates from Let's Encrypt, DigiCert, etc.

### 2. Add the Server CA to the App's Trust Store
- If using a self-signed certificate, you can bundle the CA certificate in the app and configure the network client to trust it.
- This does **not** require a client `.p12` certificate but allows HTTPS connection.
- Example in React Native:
```typescript
import {NetworkClient} from '@mattermost/react-native-network-client';

const client = new NetworkClient({
    baseURL: 'https://your-server.com',
    trustedCerts: ['server_ca.pem'], // bundle CA cert in app
});
```

### 3. Disable SSL Verification (Not Recommended)
- Only for development/testing.
- You can bypass SSL verification using custom network client settings.
- **Warning:** This is insecure and should never be used in production.
```typescript
const client = new NetworkClient({
    baseURL: 'https://your-server.com',
    disableSSLVerification: true, // insecure
});
```

### Notes
- Desktop apps often have access to broader system CA stores and can handle self-signed certificates more leniently.
- Mobile apps, particularly on Android, are sandboxed and stricter about SSL validation.
- There is **no official way** to fully replicate desktop leniency in Android without either:
  1. Providing a trusted certificate.
  2. Bundling CA certificate.
  3. Disabling SSL verification (not secure).

## References
- [Mattermost React Native Network Client GitHub](https://github.com/mattermost/react-native-network-client)
- [Android Network Security Config](https://developer.android.com/training/articles/security-config)
- [React Native HTTPS Requests](https://reactnative.dev/docs/network)
```


