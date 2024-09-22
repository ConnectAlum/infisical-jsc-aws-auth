# Infisical JS Client - AWS Auth

This is a implementation of [AWS Auth](https://infisical.com/docs/documentation/platform/identities/aws-auth) for [`@connectalum/infisical-js-client`](https://github.com/ConnectAlum/infisical-js-client).

**Make sure you configure AWS Auth on Infisical first. [Guide](https://infisical.com/docs/documentation/platform/identities/aws-auth#guide)**

Example usage:
```ts
import { createInfisicalClient } from "@connectalum/infisical-js-client";
import { AWSAuth } from "@connectalum/infisical-jsc-aws-auth";

const siteUrl = "https://app.infisical.com"
const infisical = createInfisicalClient({
    auth: new AWSAuth({
      identityId: "your-infisical-identity"
    }, siteUrl),
    siteUrl,
})
```
