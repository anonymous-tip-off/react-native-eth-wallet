import { generateSecureRandom } from 'react-native-securerandom';
const curveByName = require('ecurve-names');
const BigInteger = require('bigi');
const keccak256 = require('js-sha3').keccak256;

const integerToBytes = (i, len) => {
    let bytes = i.toByteArrayUnsigned();
    if (len < bytes.length) {
        bytes = bytes.slice(bytes.length - len);
    } else while (len > bytes.length) {
        bytes.unshift(0);
    }

    return bytes;
}

export default walletUtils = {

    async createPrivateKey() {
        const randomBytes = await generateSecureRandom(32);

        const privateKeyBytes = [];
        for (let i = 0; i < randomBytes.length; ++i) {
            privateKeyBytes[i] = randomBytes[i];
        }

        return Array.from(privateKeyBytes, (byte) => {
            return ('0' + (byte & 0xFF).toString(16)).slice(-2);
        }).join('');
    },

    async createPrivateKeyFromRandomness(randomness) {
        const randomBytes = randomness;

        const privateKeyBytes = [];
        for (let i = 0; i < randomBytes.length; ++i) {
            privateKeyBytes[i] = randomBytes[i];
        }

        return Array.from(privateKeyBytes, (byte) => {
            return ('0' + (byte & 0xFF).toString(16)).slice(-2);
        }).join('');
    },

    getPublicKey(privateKey) {
        if (privateKey.length < 64 || privateKey.length > 66) {
            return false;
        }

        const privateKeyBytes = [];
        for (let i = 0; i < privateKey.length; i += 2) {
            privateKeyBytes.push(parseInt(privateKey.substr(i, 2), 16));
        }

        const privateKeyBN = BigInteger.fromByteArrayUnsigned(privateKeyBytes);

        const curve = curveByName('secp256k1');
        const curvePt = curve.getG().multiply(privateKeyBN);

        const x = curvePt.getX().toBigInteger();
        const y = curvePt.getY().toBigInteger();

        let publicKeyBytes = integerToBytes(x, 32);
        publicKeyBytes = publicKeyBytes.concat(integerToBytes(y, 32));

        return Array.from(publicKeyBytes, (byte) => {
            return ('0' + (byte & 0xFF).toString(16)).slice(-2);
        }).join('');
    },

    convertToEthereumAddress(publicKey) {
        const publicKeyBytes = [];
        for (let i = 0; i < publicKey.length; i += 2) {
            publicKeyBytes.push(parseInt(publicKey.substr(i, 2), 16));
        }

        const address = keccak256(publicKeyBytes).slice(24);

        return '0x' + address;
    },

    addChecksum(address) {
        address = address.toLowerCase().replace('0x', '');
        const hash = keccak256(address);
        let checksummedAddress = '0x';

        for (let i = 0; i < address.length; i++) {
            if (parseInt(hash[i], 16) >= 8) {
                checksummedAddress += address[i].toUpperCase();
            } else {
                checksummedAddress += address[i];
            }
        }

        return checksummedAddress;
    }

}

console.log(generateSecureRandom(32));