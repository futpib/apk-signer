import test from 'ava';
import {runParser} from '@futpib/parser';
import {androidPackageParser} from '@futpib/parser/build/androidPackageParser.js';
import {uint8ArrayParserInputCompanion} from '@futpib/parser/build/parserInputCompanion.js';
import {uint8ArrayAsyncIterableToUint8Array} from '@futpib/parser/build/uint8Array.js';
import {signApk} from './sign.js';

const debugKeystoreCid = 'bafkreibeonabgxzrmcpkrqjz6wvgono2qaqi2p5fmd43hvgzypzcnm3mgy';
const unsignedApkCid = 'bafkreig4z3omzuc3g3zp4t26coodtfmtumifvvtfupdi4essrwbvs45phy';
const signedApkCid = 'bafkreidccgxv2jq3hnio73i4etdamhy7ufsjnwesvlkafqjskro34umabu';

async function fetchCidStream(cid: string) {
	const response = await fetch('https://ipfs.io/ipfs/' + cid);
	return response.body!;
}

test('signApk', async t => {
	const keystoreStream = await fetchCidStream(debugKeystoreCid);
	const keystoreUint8Array = await uint8ArrayAsyncIterableToUint8Array(keystoreStream);

	const unsignedApkStream = await fetchCidStream(unsignedApkCid);
	const expectedSignedApkStream = await fetchCidStream(signedApkCid);

	const actualSignedApkStream = signApk({
		apk: unsignedApkStream,
		keystore: keystoreUint8Array,
		keystorePassword: 'android',
	});

	const actualSignedApk = await runParser(androidPackageParser, actualSignedApkStream, uint8ArrayParserInputCompanion);
	const expectedSignedApk = await runParser(androidPackageParser, expectedSignedApkStream, uint8ArrayParserInputCompanion);

	t.deepEqual(actualSignedApk, expectedSignedApk);
});
