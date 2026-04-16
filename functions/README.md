## Admin Login Function

This function moves admin password verification off the frontend.

Required environment variables:

- `ADMIN_EMAIL`
- `ADMIN_PASS_HASH`
- `FIREBASE_API_KEY`
- `FIREBASE_AUTH_DOMAIN`
- `FIREBASE_PROJECT_ID`
- `FIREBASE_STORAGE_BUCKET`
- `FIREBASE_MESSAGING_SENDER_ID`
- `FIREBASE_APP_ID`
- `FIREBASE_MEASUREMENT_ID`

`ADMIN_PASS_HASH` should be the SHA-256 hash of the admin password, matching the app's existing hashing format.

Typical deploy flow:

1. Install dependencies in `functions/`
2. Set the function environment variables/secrets for `ADMIN_EMAIL` and `ADMIN_PASS_HASH`
3. Deploy the Firebase functions:

```bash
firebase deploy --only functions:appConfig,functions:adminLogin
```
