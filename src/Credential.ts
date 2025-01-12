export enum CredentialType {
	BASIC = 1
}

export abstract class Credential {
	readonly abstract type: CredentialType;
}

export class BasicCredential extends Credential {
	readonly type = CredentialType.BASIC;
}
