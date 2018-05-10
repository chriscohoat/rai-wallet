const { RaiFunctions } = require('./')

const pubKey = '0D7471E5D11FADDCE5315C97B23B464184AFA8C4C396DCF219696B2682D0ADF6'
const account = 'xrb_15dng9kx49xfumkm4q6qpaxneie6oynebiwpums3ktdd6t3f3dhp69nxgb38'
const nano_account = 'nano_15dng9kx49xfumkm4q6qpaxneie6oynebiwpums3ktdd6t3f3dhp69nxgb38'

const derivedAccount = RaiFunctions.accountFromHexKey(pubKey)
const derivedKey = RaiFunctions.keyFromAccount(account)
const derivedKey2 = RaiFunctions.keyFromAccount(nano_account)

console.log(pubKey)
console.log(derivedKey)
console.log(derivedKey2);
console.log()
console.log(account)
console.log(derivedAccount)