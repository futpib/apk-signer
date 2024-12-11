import crypto from 'node:crypto';
import forge from 'node-forge';
import { runParser } from '@futpib/parser';
import { runUnparser } from '@futpib/parser/build/unparser.js';
import { apkSignatureV2SignedDataUnparser, apkSigningBlockUnparser } from '@futpib/parser/build/apkUnparser.js';
import { zipEndOfCentralDirectoryRecordParser } from '@futpib/parser/build/zipParser.js';
import { zipEndOfCentralDirectoryRecordUnparser } from '@futpib/parser/build/zipUnparser.js';
import { apkSignableSectionsParser } from '@futpib/parser/build/apkParser.js';
import { uint8ArrayParserInputCompanion } from '@futpib/parser/build/parserInputCompanion.js';
import { uint8ArrayUnparserOutputCompanion } from '@futpib/parser/build/unparserOutputCompanion.js';
import invariant from 'invariant';
import { ApkSignatureV2, ApkSignatureV2Signer, ApkSigningBlock } from '@futpib/parser/build/apk.js';
import { uint8ArrayAsyncIterableToUint8Array } from '@futpib/parser/build/uint8Array.js';

function apkSignableSectionToChunks(uint8Array: Uint8Array) {
	const chunkSize = 2 ** 20;
	const chunkCount = Math.ceil(uint8Array.length / chunkSize);
	const chunks: Uint8Array[] = [];

	for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex++) {
		const chunkStart = chunkIndex * chunkSize;
		const chunkEnd = chunkStart + chunkSize;
		const chunk = uint8Array.subarray(chunkStart, chunkEnd);
		chunks.push(chunk);
	}

	return chunks;
}

async function hashChunk(uint8Array: Uint8Array) {
	const hash = crypto.createHash('sha256');
	hash.update(new Uint8Array([ 0xA5 ]));
	const lengthBuffer = Buffer.alloc(4);
	lengthBuffer.writeUInt32LE(uint8Array.length);
	hash.update(lengthBuffer);
	hash.update(uint8Array);
	return hash.digest();
}

async function hashChunkHashes(chunkHashes: Uint8Array[]) {
	const hash = crypto.createHash('sha256');
	hash.update(new Uint8Array([ 0x5A ]));
	const lengthBuffer = Buffer.alloc(4);
	lengthBuffer.writeUInt32LE(chunkHashes.length);
	hash.update(lengthBuffer);
	for (const chunkHash of chunkHashes) {
		hash.update(chunkHash);
	}
	return hash.digest();
}

function hashChunkHashesWithForge(chunkHashes: Uint8Array[]) {
	const messageDigest = forge.md.sha256.create();
	messageDigest.update(forge.util.binary.raw.encode(new Uint8Array([ 0x5A ])));
	const lengthBuffer = Buffer.alloc(4);
	lengthBuffer.writeUInt32LE(chunkHashes.length);
	messageDigest.update(forge.util.binary.raw.encode(lengthBuffer));
	for (const chunkHash of chunkHashes) {
		messageDigest.update(forge.util.binary.raw.encode(chunkHash));
	}
	return messageDigest;
}

export async function hashApkSignableSections(apkSignableSections: Uint8Array[]) {
	const chunks = apkSignableSections.flatMap(apkSignableSectionToChunks);
	const chunkHashes = await Promise.all(chunks.map(hashChunk));
	const apkSignableSectionsMessageDigest = hashChunkHashesWithForge(chunkHashes);

	return apkSignableSectionsMessageDigest;
}

export async function hashApkSignableSections_(apkSignableSections: Uint8Array[]) {
	const chunks = apkSignableSections.flatMap(apkSignableSectionToChunks);
	const chunkHashes = await Promise.all(chunks.map(hashChunk));
	const apkSignableSectionsMessageDigest = await hashChunkHashes(chunkHashes);

	return apkSignableSectionsMessageDigest;
}

const signatureAlgorithmId = 0x0103;

export async function * signApk({
	apk,
	keystore,
	keystorePassword,
}: {
	apk: Uint8Array | AsyncIterable<Uint8Array>;
	keystore: Uint8Array;
	keystorePassword: string;
}): AsyncIterable<Uint8Array> {
	const unsignedApkSignableSections = await runParser(apkSignableSectionsParser, apk, uint8ArrayParserInputCompanion);

	const {
		zipLocalFilesUint8Array,
		zipCentralDirectoryUint8Array,
		zipEndOfCentralDirectoryUint8Array,
	} = unsignedApkSignableSections;

	const apkSignableSectionsMessageDigest = await hashApkSignableSections([
		zipLocalFilesUint8Array,
		zipCentralDirectoryUint8Array,
		zipEndOfCentralDirectoryUint8Array,
	]);

	const keystoreBytes = forge.util.binary.raw.encode(keystore);
	const p12Asn1 = forge.asn1.fromDer(keystoreBytes);
	const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, keystorePassword);

	const certificateBags = p12.getBags({ bagType: forge.pki.oids.certBag });
	const firstCertificateBag = certificateBags[forge.pki.oids.certBag]?.at(0);
	const certificate = firstCertificateBag?.cert;
	const shroudedKeyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
	const firstShroudedKeyBag = shroudedKeyBags[forge.pki.oids.pkcs8ShroudedKeyBag]?.at(0);
	const key = firstShroudedKeyBag?.key;

	invariant(certificate, 'No certificate found in keystore');
	invariant(key, 'No key found in keystore');

	invariant(!(key instanceof Uint8Array), 'Key is not a pki rsa key');

	const digest = forge.util.binary.raw.decode(
		apkSignableSectionsMessageDigest.digest().getBytes(),
	);

	const certificateUint8Array = forge.util.binary.raw.decode(
		forge.asn1.toDer(
			forge.pki.certificateToAsn1(certificate)
		).getBytes()
	);

	const signedData = {
		digests: [
			{
				signatureAlgorithmId,
				digest,
			},
		],
		certificates: [
			certificateUint8Array,
		],
		additionalAttributes: [],
		zeroPaddingLength: 4,
	};

	const signedDataUint8Array = await uint8ArrayAsyncIterableToUint8Array(
		runUnparser(
			apkSignatureV2SignedDataUnparser,
			signedData,
			uint8ArrayUnparserOutputCompanion,
		),
	);

	const signedDataDigest = forge.md.sha256.create();
	signedDataDigest.update(
		forge.util.binary.raw.encode(
			signedDataUint8Array.subarray(4),
		),
	);

	const signatureBytes = key.sign(
		signedDataDigest,
		'RSASSA-PKCS1-V1_5',
	);
	const signature = forge.util.binary.raw.decode(signatureBytes);

	const publicKeyFromPrivateKey = forge.pki.rsa.setPublicKey(key.n, key.e);
	const publicKeyFromCertificate = certificate.publicKey;

	invariant(!(publicKeyFromCertificate instanceof Uint8Array), 'Key is not a pki rsa key');

	invariant(
		publicKeyFromPrivateKey.n.equals(publicKeyFromCertificate.n)
			&& publicKeyFromPrivateKey.e.equals(publicKeyFromCertificate.e),
		'Public key from private key does not match public key from certificate',
	);

	const publicKeyUint8Array = forge.util.binary.raw.decode(
		forge.asn1.toDer(
			forge.pki.publicKeyToAsn1(
				publicKeyFromPrivateKey
			)
		).getBytes()
	);

	const signer: ApkSignatureV2Signer = {
		signedData,
		signatures: [
			{
				signatureAlgorithmId,
				signature,
			},
		],
		publicKey: publicKeyUint8Array,
	};

	const signatureV2: ApkSignatureV2 = {
		signers: [
			signer,
		],
	};

	const apkSigningBlock: ApkSigningBlock = {
		pairs: [],
		signatureV2,
		zeroPaddingLength: 2650,
	};

	const zipEndOfCentralDirectoryRecord = await runParser(zipEndOfCentralDirectoryRecordParser, zipEndOfCentralDirectoryUint8Array, uint8ArrayParserInputCompanion);

	yield * runUnparser(async function * (_input, unparserContext) {
		yield zipLocalFilesUint8Array;

		yield * runUnparser(apkSigningBlockUnparser, apkSigningBlock, uint8ArrayUnparserOutputCompanion);

		const startOfCentralDirectory = unparserContext.position;

		yield zipCentralDirectoryUint8Array;

		yield * runUnparser(zipEndOfCentralDirectoryRecordUnparser, {
			...zipEndOfCentralDirectoryRecord,
			offsetOfStartOfCentralDirectoryWithRespectToTheStartingDiskNumber: startOfCentralDirectory,
		}, uint8ArrayUnparserOutputCompanion);
	}, undefined, uint8ArrayUnparserOutputCompanion);
}
