import test from 'ava';
import { verifyApk } from './verify.js';

const signedApkCid = 'bafkreidccgxv2jq3hnio73i4etdamhy7ufsjnwesvlkafqjskro34umabu'

async function fetchCidStream(cid: string) {
	const response = await fetch('https://ipfs.io/ipfs/' + cid);
	return response.body!;
}

test('verifyApk', async t => {
	const signedApkStream = await fetchCidStream(signedApkCid);

	const verified = await verifyApk({
		apk: signedApkStream,
	});

	t.true(verified);
});
