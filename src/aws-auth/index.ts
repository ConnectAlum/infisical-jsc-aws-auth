import { Auth } from "@connectalum/infisical-js-client";
import { sign } from "aws4";
type AWSAuthOptions = {
  identityId: string;
  region?: string;
}

type AWSAuthResponse = {
  accessToken: string;
  expiresIn: number;
  accessTokenMaxTTL: number;
  tokenType: "Bearer";
};

export class AWSAuth implements Auth<AWSAuthOptions> {
  currentAuth: AWSAuthResponse | null = null;
  constructor(public auth: AWSAuthOptions, public siteUrl: string) { }
  async authenticate(): Promise<string> {
    const region = this.auth.region ?? process.env.AWS_REGION;
    const iamRequestURL = `https://sts.${region}.amazonaws.com/`;
    const iamRequestBody = "Action=GetCallerIdentity&Version=2011-06-15";
    const iamRequestHeaders = {
      "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
      Host: `sts.${region}.amazonaws.com`
    };
    const opts = {
      service: "sts",
      region,
      path: "/",
      headers: iamRequestHeaders,
      body: iamRequestBody
    }
    sign(opts);
    // fetch
    const response = await fetch(`${this.siteUrl}/api/v1/auth/aws-auth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        identityId: this.auth.identityId,
        iamHttpRequestMethod: "POST",
        iamRequestUrl: Buffer.from(iamRequestURL).toString("base64"),
        iamRequestBody: Buffer.from(opts.body).toString("base64"),
        iamRequestHeaders: Buffer.from(JSON.stringify(opts.headers)).toString("base64"),
      })
    }).catch((e) => {
      throw e;
    })
    const data = await response.json();
    this.currentAuth = data;
    return data.accessToken;
  }
  getAccessToken(): Promise<string> {
    if (this.currentAuth === null) {
      return this.authenticate();
    }
    return Promise.resolve(this.currentAuth.accessToken);
  }
}