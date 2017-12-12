# rai-wallet [![npm][npm-image]][npm-url] [![downloads][downloads-image]][downloads-url] [![javascript style guide][standard-image]][standard-url]

[npm-image]: https://img.shields.io/npm/v/rai-wallet.svg
[npm-url]: https://npmjs.org/package/rai-wallet
[downloads-image]: https://img.shields.io/npm/dm/rai-wallet.svg
[downloads-url]: https://npmjs.org/package/rai-wallet
[standard-image]: https://img.shields.io/badge/code_style-standard-brightgreen.svg
[standard-url]: https://standardjs.com

Creates ciphered RaiBlocks wallets for client-side and offline use

## Installation

```
yarn add rai-wallet
```

or

```
npm install --save rai-wallet
```

## Usage

### ES5

```
var RaiWallet = require('rai-wallet');
var Wallet = RaiWallet.Wallet;
```

### ES6

```
import { Wallet } from 'rai-wallet';
const wallet = new Wallet('password');
```

## Development

In this directory:

```
yarn link
```

In the directory you are working with `rai-wallet`:

```
yarn link rai-wallet
```