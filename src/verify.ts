import forge from 'node-forge';
import { runParser } from '@futpib/parser';
import { androidPackageSignableSectionsParser } from '@futpib/parser/build/androidPackageParser.js';
import { uint8ArrayParserInputCompanion } from '@futpib/parser/build/parserInputCompanion.js';
import {zipEndOfCentralDirectoryRecordParser} from '@futpib/parser/build/zipParser.js';
import {runUnparser} from '@futpib/parser/build/unparser.js';
import {zipEndOfCentralDirectoryRecordUnparser} from '@futpib/parser/build/zipUnparser.js';
import {uint8ArrayUnparserOutputCompanion} from '@futpib/parser/build/unparserOutputCompanion.js';
import invariant from 'invariant';
import {androidPackageSignatureV2SignedDataUnparser} from '@futpib/parser/build/androidPackageUnparser.js';
import {uint8ArrayAsyncIterableToUint8Array} from '@futpib/parser/build/uint8Array.js';
import {hashApkSignableSections} from './sign.js';

export async function verifyApk({
	apk,
}: {
	apk: Uint8Array | AsyncIterable<Uint8Array>;
}) {
	const signedApkSignableSections = await runParser(androidPackageSignableSectionsParser, apk, uint8ArrayParserInputCompanion);

	const {
		zipLocalFilesUint8Array,
		zipCentralDirectoryUint8Array,
		zipEndOfCentralDirectoryUint8Array,

		androidPackageSigningBlock,
	} = signedApkSignableSections;

	invariant(androidPackageSigningBlock, 'APK signing block must be present');

	const signer = androidPackageSigningBlock.signatureV2?.signers.at(0);

	invariant(signer, 'APK signer must be present');

	const zipEndOfCentralDirectoryRecord = await runParser(zipEndOfCentralDirectoryRecordParser, zipEndOfCentralDirectoryUint8Array, uint8ArrayParserInputCompanion);

	const modifiedZipEndOfCentralDirectoryStream = runUnparser(zipEndOfCentralDirectoryRecordUnparser, {
		...zipEndOfCentralDirectoryRecord,
		offsetOfStartOfCentralDirectoryWithRespectToTheStartingDiskNumber: zipLocalFilesUint8Array.length,
	}, uint8ArrayUnparserOutputCompanion);

	const modifiedZipEndOfCentralDirectoryUint8Array = Buffer.concat(await (async () => {
		const chunks: Uint8Array[] = [];
		for await (const chunk of modifiedZipEndOfCentralDirectoryStream) {
			chunks.push(chunk);
		}

		return chunks;
	})());

	const apkSignableSectionsMessageDigest = await hashApkSignableSections([
		zipLocalFilesUint8Array,
		zipCentralDirectoryUint8Array,
		modifiedZipEndOfCentralDirectoryUint8Array,
	]);

	const actualDigest = forge.util.binary.raw.decode(
		apkSignableSectionsMessageDigest.digest().getBytes(),
	);

	const expectedDigest = (
		signer.signedData.digests
			.find(digest => digest.signatureAlgorithmId === 0x01_03)?.digest
	);

	invariant(expectedDigest, 'A digest must be present in the signed apk');
	invariant(Buffer.from(expectedDigest).equals(actualDigest), 'Digest in the signed apk does not match the computed digest');

	const certificateUint8Array = signer.signedData.certificates.at(0);

	invariant(certificateUint8Array, 'A certificate must be present in the signed apk');

	const certificate = forge.pki.certificateFromAsn1(
		forge.asn1.fromDer(
			forge.util.binary.raw.encode(certificateUint8Array),
		),
	);

	const publicKeyFromCertificate = certificate.publicKey;
	const publicKeyFromSigner = forge.pki.publicKeyFromAsn1(
		forge.asn1.fromDer(
			forge.util.binary.raw.encode(
				signer.publicKey,
			),
		),
	);

	invariant(!(publicKeyFromCertificate instanceof Uint8Array), 'Public key is not a pki rsa key');
	invariant(!(publicKeyFromSigner instanceof Uint8Array), 'Public key is not a pki rsa key');

	invariant(
		publicKeyFromSigner.n.equals(publicKeyFromCertificate.n)
			&& publicKeyFromSigner.e.equals(publicKeyFromCertificate.e),
		'Public key from private key does not match public key from certificate',
	);

	const signatureUint8Array = signer.signatures.find(signature => signature.signatureAlgorithmId === 0x01_03)?.signature;

	invariant(signatureUint8Array, 'A signature must be present in the signed apk');

	const signedDataAsyncIterable = runUnparser(androidPackageSignatureV2SignedDataUnparser, signer.signedData, uint8ArrayUnparserOutputCompanion);
	const signedDataUint8Array = await uint8ArrayAsyncIterableToUint8Array(signedDataAsyncIterable);
	const modifiedSignedDataUint8Array = signedDataUint8Array.subarray(4);

	const signedDataDigest = forge.md.sha256.create();
	signedDataDigest.update(
		forge.util.binary.raw.encode(
			modifiedSignedDataUint8Array,
		),
	);

	return publicKeyFromSigner.verify(
		signedDataDigest.digest().getBytes(),
		forge.util.binary.raw.encode(signatureUint8Array),
		'RSASSA-PKCS1-V1_5',
	);
}
