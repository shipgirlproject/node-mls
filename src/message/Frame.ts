import { Buffer } from 'node:buffer';

export enum ProtocolVersion {
	RESERVED,
	MLS10
}

export enum ContentType {
	RESERVED,
	APPLICATION,
	PROPOSAL,
	COMMIT
}

export enum SenderType {
	RESERVED,
	MEMBER,
	EXTERNAL,
	NEW_MEMBER_PROPOSAL,
	NEW_MEMBER_COMMIT
}

export enum MessageType {
	PUBLIC_MESSAGE,
	PRIVATE_MESSAGE,
	WELCOME,
	GROUP_INFO,
	KEY_PACKAGE
}

export abstract class Sender {
	public abstract readonly type: SenderType;
}

export class MemberSender extends Sender {
	public readonly type = SenderType.MEMBER;
	constructor (
		public readonly leafIndex: number
	) {
		super();
	}
}

export class ExternalSender extends Sender {
	public readonly type = SenderType.EXTERNAL;
	constructor (
		public readonly senderIndex: number
	) {
		super();
	}
}

export class NewMemberCommitSender extends Sender {
	public readonly type = SenderType.NEW_MEMBER_COMMIT;
}

export class NewMemberProposalSender extends Sender {
	public readonly type = SenderType.NEW_MEMBER_PROPOSAL;
}

export abstract class FramedContent {
	public groupId?: Buffer;
	public epoch?: number;
	public sender?: Sender;
	public authenticatedData?: Buffer;
	public abstract readonly contentType: ContentType;
}

export class ApplicationFramedContent extends FramedContent {
	public readonly contentType = ContentType.APPLICATION;
	public applicationData?: Buffer;
}

export class ProposalFramedContent extends FramedContent {
	public readonly contentType = ContentType.PROPOSAL;
	// TODO: impl
	public proposal?: string;
}

export class CommitFramedContent extends FramedContent {
	public readonly contentType = ContentType.COMMIT;
	// TODO: impl
	public commit?: string;
}

export abstract class MLSMessage {
	public readonly version = ProtocolVersion.MLS10;
}

export class MLSPublicMessage extends MLSMessage {
	public readonly wireFormat = MessageType.PUBLIC_MESSAGE;
	// TODO: impl
	public publicMessage?: string;
}

export class MLSPrivateMessage extends MLSMessage {
	public readonly wireFormat = MessageType.PRIVATE_MESSAGE;
	// TODO: impl
	public privateMessage?: string;
}

export class MLSWelcome extends MLSMessage {
	public readonly wireFormat = MessageType.WELCOME;
	// TODO: impl
	public welcome?: string;
}

export class MLSGroupInfo extends MLSMessage {
	public readonly wireFormat = MessageType.GROUP_INFO;
	// TODO: impl
	public groupInfo?: string;
}

export class MLSKeyPackage extends MLSMessage {
	public readonly wireFormat = MessageType.KEY_PACKAGE;
	// TODO: impl
	public keyPackage?: string;
}
