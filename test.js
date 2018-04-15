const { RaiFunctions, Wallet, Block } = require('./')

/**
 * RaiFunctions tests
 */
const pubKey = '0D7471E5D11FADDCE5315C97B23B464184AFA8C4C396DCF219696B2682D0ADF6'
const account = 'xrb_15dng9kx49xfumkm4q6qpaxneie6oynebiwpums3ktdd6t3f3dhp69nxgb38'

const derivedAccount = RaiFunctions.accountFromHexKey(pubKey)
const derivedKey = RaiFunctions.keyFromAccount(account)

console.log(pubKey)
console.log(derivedKey)
console.log()
console.log(account)
console.log(derivedAccount)

/**
 * State blocks tests
 */

 // open block based on the example here -> https://github.com/nanocurrency/raiblocks/wiki/Universal-Blocks-Specification
var stateBlocksTestWallet = new Wallet();
stateBlocksTestWallet.createWallet('168728029C60D62D37C6902FE9A3FFC78E9685A410EB3E937AEABAC2BE199689');
var blk = stateBlocksTestWallet.addPendingReceiveBlock('1EF0AD02257987B48030CC8D38511D3B2511672F33AF115AD09E18A86A8355A8', stateBlocksTestWallet.getAccounts()[0].account, false, 1, 'xrb_3p1asma84n8k84joneka776q4egm5wwru3suho9wjsfyuem8j95b3c78nw8j');

console.log();
console.log(blk.getHash(true));
console.log('FC5A7FB777110A858052468D448B2DF22B648943C097C0608D1E2341007438B0');