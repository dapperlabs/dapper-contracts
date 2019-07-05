const utils = require("./utils");
const walletutils = require("./wallet-utils");
const abi = require('ethereumjs-abi');
const ethUtils = require('ethereumjs-util');
const cTable = require('console.table');
const crypto = require("crypto");

const FullWallet = artifacts.require('./Wallet/FullWallet.sol');
const QueryableWallet = artifacts.require("./Wallet/QueryableWallet.sol");
const ERC165Checker = artifacts.require('./ERC165Checker.sol');
const StandardTokenMock = artifacts.require('./Test/StandardTokenMock.sol');
const ERC721TokenMock = artifacts.require('./Test/ERC721TokenMock.sol');
const ThrowOnPayable = artifacts.require('./Test/ThrowOnPayable.sol');
const SimpleWallet = artifacts.require('./Test/SimpleWallet.sol');
const Selector = artifacts.require('./Test/Selector.sol');
const Delegate = artifacts.require('./Test/Delegate.sol');
const { bytecode: fullBytecode } = require('../build/contracts/FullWallet.json');

require('chai').should();

// these are the corresponding private keys to the 'accounts' array
const privateKeys = [
    Buffer.from('c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3', 'hex'),
    Buffer.from('ae6ae8e5ccbfb04590405997ee2d52d2b330726137b875053c36d94e974d162f', 'hex'),
    Buffer.from('0dbbe8e4ae425a6d2687f1a7e3ba17bc98c673636790f1b8ad91193c05875ef1', 'hex'),
    Buffer.from('c88b703fb08cbea894b6aeff5a544fb92e78a18e19814cd85da83b71f772aa6c', 'hex'),
    Buffer.from('388c684f0ba1ef5017716adb5d21a053ea8e90277d0868337519f97bede61418', 'hex'),
    Buffer.from('659cbb0e2411a44db63778987b1e22153c086a95eb6b18bdf89de078917abc63', 'hex'),
    Buffer.from('82d052c865f5763aad42add438569276c00d3d88a2d062d36b2bae914d58b8c8', 'hex'),
    Buffer.from('aa3680d5d48a8283413f7a108367c7299ca73f553735860a87b08f39395618b7', 'hex'),
    Buffer.from('0f62d96d6675f32685bbdb8ac13cda7c23436f63efbb9d07700d8669ff12b7c4', 'hex'),
    Buffer.from('8d5366123cb560bb606379f90a0bfd4769eecc0557f1b362dcae9012b548b1e5', 'hex')
];

const zeroAddress = '0x0000000000000000000000000000000000000000';
// EIP-155 37/38 not supported by `ecrecover` as far as I can tell

/**
 * 
 * @param {string} _transferAmount amount in wei string
 * @param {string} _fundAmount amount in wei string
 * @param {*} _walletAddress 
 * @param {*} _ethRecipient 
 * @param {BN} _ethRecipientOrigBalance original balance as a BN
 */
const checkBalances = async function (_transferAmount, _fundAmount, _walletAddress, _ethRecipient, _ethRecipientOrigBalance) {
    const tBig = web3.utils.toBN(_transferAmount);
    const remaining = web3.utils.toBN(_fundAmount).sub(tBig);
    // left in wallet
    const walletBalWei = web3.utils.toBN(await web3.eth.getBalance(_walletAddress));
    walletBalWei.eq(remaining).should.eql(true);
    // recipientAmount
    const recipientBalWei = web3.utils.toBN(await web3.eth.getBalance(_ethRecipient));
    // receiver amount
    recipientBalWei.eq(tBig.add(_ethRecipientOrigBalance)).should.eql(true);
};


// method
const BASE = 0;
const INVOKE0 = 1;
const INVOKE1 = 2;
const INVOKE11 = 3;
const INVOKE2 = 4;
// operation
const TRANSFER_ETH = "Ξ Transfer";
const TRANSFER_ERC20 = "ERC20 Transfer";
const TRANSFER_ERC721 = "ERC721 Transfer";
const TRANSFER_MULTI = "Multi Transfer";

// global prices
let gasPrices = [];

const logGasPrice = function (wtype, method, operation, gas) {
    // method and type pick row
    let obj = {};
    obj[operation] = gas;
    let i = wtype * 5 + method;
    if (wtype == walletutils.WALLET_CLONE || wtype == walletutils.WALLET_CLONE_2) {
        i -= 1;
    }
    gasPrices[i] = { ...gasPrices[i], ...obj };
};

const getGasPrice = function (wtype, method) {
    let i = wtype * 5 + method;
    if (wtype == walletutils.WALLET_CLONE) {
        i -= 1;
    }
    return gasPrices[i];
}

const setRecoveryAddressData = (newAddr) => {
    // need to invoke
    let dataArr = [];
    // function signature
    dataArr.push(utils.funcHash('setRecoveryAddress(address)'));
    // arg: new recovery address
    dataArr.push(utils.numToBuffer(newAddr));
    return Buffer.concat(dataArr);
};

const setDelegateData = (methodID, delegate) => {
    let dataArr = [];
    dataArr.push(utils.funcHash('setDelegate(bytes4,address)'));
    dataArr.push(Buffer.from(utils.padBytes4(methodID), 'hex'));
    dataArr.push(abi.rawEncode(['address'], [delegate]));
    return Buffer.concat(dataArr);
}

// TODO: load abi and auto-calculate this
const SET_AUTHORIZED_SIGNATURE = 'setAuthorized(address,uint256)';

const setAuthorizedData = (signer, cosigner) => {
    // add a key
    // have to do it through invoke
    var dataArr = [];
    // function signature
    dataArr.push(utils.funcHash(SET_AUTHORIZED_SIGNATURE));
    // arg: authorized addr
    dataArr.push(utils.numToBuffer(signer));
    // arg: cosigner addr
    dataArr.push(utils.numToBuffer(cosigner));
    return Buffer.concat(dataArr);
};

function incrementCharAt(str, index) {
    if (index > str.length -1) return str;

    // ensure we keep it as hex
    const code = str.charAt(index).charCodeAt(0);
    if (code === 'f'.charCodeAt(0) || code === '9'.charCodeAt(0)) {
        return str.substr(0, index) + String.fromCharCode(code - 1) + str.substr(index + 1);
    } else {
        return str.substr(0, index) + String.fromCharCode(code + 1) + str.substr(index + 1);
    }
}

const testSuite = async function (wtype, accounts, _walletFactory, _cloneAddress) {

    let wallet;
    const funder = accounts[0];
    const fundAmount = web3.utils.toWei("100000000", "gwei"); // 0.1 ETH

    describe('when wallet is created', function () {

        const masterPublicKey = accounts[8];
        //const masterPublicKey = '0x6330a553fc93768f612722bb8c2ec78ac90b3bbc';
        const masterPrivateKey = privateKeys[8];
        const adminPublicKey = accounts[7];
        //const adminPublicKey = '0x0f4f2ac550a1b4e2280d04c21cea7ebd822934b5';
        const adminPrivateKey = privateKeys[7];
        let cosignerPublicKey = accounts[5];
        let fullCosignerKey;
        let cosignerPrivateKey = privateKeys[5];
        // cannot add more than 0x4000000, see https://github.com/ethereum/web3.js/issues/2171 and https://github.com/indutny/bn.js/issues/176
        const metaData = web3.utils.toBN("0").add(web3.utils.toBN('0xDEADBEEFDEADBEEFDEADBEEF0000000000000000000000000000000000000000', 16));

        // create2 salt
        let salt;

        beforeEach(function () {
            // initialize a salt; must be different each time
            salt = '0x' + crypto.randomBytes(32).toString('hex');
        });

        describe('with a cosigner', function () {

            beforeEach(async function () {
                // create a cosigner key
                fullCosignerKey = metaData.add(web3.utils.toBN(cosignerPublicKey));
                //fullCosignerKey = '0xdeadbeefdeadbeefdeadbeef2932b7a2355d6fecc4b5c0b6bd44cc31df247a2e';
                //console.log('cosigning key:' + fullKey.toString(16));

                wallet = await walletutils.createWallet(
                    wtype,
                    masterPublicKey,
                    adminPublicKey,
                    fullCosignerKey,
                    _walletFactory,
                    salt
                );
            });

            it('should be able to get the version', async function () {
                const version = await wallet.VERSION.call();
                version.should.eql("1.1.0");
            });

            it('should be at the expected address if using create2', async function () {
                if (wtype == walletutils.WALLET_CLONE_2) {
                    const _bytecode = "0x3d602d80600a3d3981f3363d3d373d3d3d363d73" +
                        _cloneAddress.replace("0x", "") + "5af43d82803e903d91602b57fd5bf3";
                    // we use a custom salt for this
                    const newsalt = abi.soliditySHA3(
                        ['bytes32', 'address', 'uint256', 'address'],
                        [salt, adminPublicKey, fullCosignerKey, masterPublicKey]
                    );
                    let addr = utils.buildCreate2Address(_walletFactory.address, '0x' + newsalt.toString('hex'), _bytecode);
                    addr = web3.utils.toChecksumAddress(addr);
                    addr.should.eql(wallet.address);
                } else if (wtype == walletutils.WALLET_REGULAR_2) {
                    // get the bytecode from the contract
                    // This works, although will not be reproduceable across platforms
                    // because of https://solidity.readthedocs.io/en/develop/metadata.html
                    //const accountBytecode = wallet.constructor.bytecode;
                    // so we have to load it from the build directly
                    // replicate what was sent to the network
                    const bytecode = `${fullBytecode}${web3.eth.abi.encodeParameter('address', adminPublicKey).slice(2)}${web3.eth.abi.encodeParameter('uint256', '0x' + fullCosignerKey.toString('hex')).slice(2)}${web3.eth.abi.encodeParameter('address', masterPublicKey).slice(2)}`
                    //console.log(bytecode);
                    let addr = utils.buildCreate2Address(_walletFactory.address, salt, bytecode);
                    addr = web3.utils.toChecksumAddress(addr);
                    addr.should.eql(wallet.address);
                }
            });

            describe('concerning ERC1271 compatibility', function () {
                const data = "hello world";
                const ERC1271_VS = "0x1626ba7e";

                it('should be able to validate a signature', async function () {
                    // prepare a signature from the signer and the cosigner
                    const dataHash = abi.soliditySHA3(['string'], [data]);
                    const hashToSign = utils.getSha3ForERC1271(
                        wallet.address,
                        dataHash
                    );

                    const sig1 = ethUtils.ecsign(hashToSign, adminPrivateKey, 0);
                    const sig2 = ethUtils.ecsign(hashToSign, cosignerPrivateKey, 0);
                    const combined = '0x' + sig1.r.toString('hex') + sig1.s.toString('hex') + Buffer.from([sig1.v]).toString('hex') +
                        sig2.r.toString('hex') + sig2.s.toString('hex') + Buffer.from([sig2.v]).toString('hex');
                    // call contract
                    const result = await wallet.isValidSignature('0x' + dataHash.toString('hex'), combined);
                    // check result
                    result.should.eql(ERC1271_VS);
                });

                it('should return 0 if provided an invalid signature', async function () {
                    const dataHash = abi.soliditySHA3(['string'], [data]);
                    const hashToSign = utils.getSha3ForERC1271(
                        wallet.address,
                        dataHash
                    );

                    const sig1 = ethUtils.ecsign(hashToSign, adminPrivateKey, 0);
                    const sig2 = ethUtils.ecsign(hashToSign, cosignerPrivateKey, 0);
                    let combined = '0x' + sig1.r.toString('hex') + sig1.s.toString('hex') + Buffer.from([sig1.v]).toString('hex') +
                        sig2.r.toString('hex') + sig2.s.toString('hex') + Buffer.from([sig2.v]).toString('hex');
                    // mess with the signature
                    combined = incrementCharAt(combined, 10);
                    // TODO: this fails more often than you think and requires more messing
                    const result = await wallet.isValidSignature('0x' + dataHash.toString('hex'), combined);
                    result.should.eql("0x00000000");
                });

                it('should return 0 if provided an invalid signature length', async function () {

                    const dataHash = abi.soliditySHA3(['string'], [data]);
                    const hashToSign = utils.getSha3ForERC1271(
                        wallet.address,
                        dataHash
                    );

                    const sig1 = ethUtils.ecsign(hashToSign, adminPrivateKey, 0);
                    const sig2 = ethUtils.ecsign(hashToSign, cosignerPrivateKey, 0);
                    const combined = '0x' + sig1.r.toString('hex') + sig1.s.toString('hex') + Buffer.from([sig1.v]).toString('hex') +
                        sig2.r.toString('hex') + sig2.s.toString('hex') + Buffer.from([sig2.v]).toString('hex');

                    const result = await wallet.isValidSignature('0x' + dataHash.toString('hex'), combined.substring(0, combined.length - 10));
                    result.should.eql("0x00000000");
                });

                it('should return 0 if only given 1 signature', async function () {
                    const dataHash = abi.soliditySHA3(['string'], [data]);
                    const hashToSign = utils.getSha3ForERC1271(
                        wallet.address,
                        dataHash
                    );

                    const sig1 = ethUtils.ecsign(hashToSign, adminPrivateKey, 0);
                    const combined = '0x' + sig1.r.toString('hex') + sig1.s.toString('hex') + Buffer.from([sig1.v]).toString('hex')
                    const result = await wallet.isValidSignature('0x' + dataHash.toString('hex'), combined);
                    result.should.eql("0x00000000");
                });

                it('should return 0 if given signature from a key that is not the cosigner', async function () {

                    const dataHash = abi.soliditySHA3(['string'], [data]);
                    const hashToSign = utils.getSha3ForERC1271(
                        wallet.address,
                        dataHash
                    );

                    const sig1 = ethUtils.ecsign(hashToSign, adminPrivateKey, 0);
                    // sign with another key
                    const sig2 = ethUtils.ecsign(hashToSign, masterPrivateKey, 0);
                    const combined = '0x' + sig1.r.toString('hex') + sig1.s.toString('hex') + Buffer.from([sig1.v]).toString('hex') +
                        sig2.r.toString('hex') + sig2.s.toString('hex') + Buffer.from([sig2.v]).toString('hex');
                    const result = await wallet.isValidSignature('0x' + dataHash.toString('hex'), combined);
                    result.should.eql("0x00000000");
                });

                it('should return 0 if given signature from a key that is not an authorized key', async function () {

                    const dataHash = abi.soliditySHA3(['string'], [data]);
                    const hashToSign = utils.getSha3ForERC1271(
                        wallet.address,
                        dataHash
                    );

                    // use cosigner as authorized key
                    const sig1 = ethUtils.ecsign(hashToSign, cosignerPrivateKey, 0);
                    const sig2 = ethUtils.ecsign(hashToSign, adminPrivateKey, 0);

                    const combined = '0x' + sig1.r.toString('hex') + sig1.s.toString('hex') + Buffer.from([sig1.v]).toString('hex') +
                        sig2.r.toString('hex') + sig2.s.toString('hex') + Buffer.from([sig2.v]).toString('hex');
                    const result = await wallet.isValidSignature('0x' + dataHash.toString('hex'), combined);
                    result.should.eql("0x00000000");
                });
            });

            it('should be able to send 0 eth', async function () {
                await walletutils.fundAddress(funder, wallet.address, web3.utils.toWei("0"));
            });

            describe('when wallet is funded', function () {
                beforeEach(async function () {
                    // fund the wallet
                    await walletutils.fundAddress(funder, wallet.address, fundAmount);
                });

                describe('when performing transactions', function () {

                    let nonce;

                    beforeEach(async function () {
                        // Run before each test. Sets the sequence ID up to be used in the tests
                        nonce = await walletutils.getNonce(wallet, adminPublicKey);
                    });

                    // Recovery tests
                    describe('concerning recovery', function () {

                        it('should not be able to call `setRecoveryAddress` directly', async function () {
                            await utils.expectThrow(
                                wallet.setRecoveryAddress(utils.newKeyPair().address)
                            );
                        });

                        it('should not be able to call `emergencyRecovery` with wrong address', async function () {

                            await utils.expectThrow(
                                wallet.emergencyRecovery(utils.newKeyPair().address, utils.newKeyPair().address, { from: accounts[0] })
                            );
                        });

                        describe('setting the recovery address to an authorized address', function () {
                            let revert;
                            describe('with revert = 0', function () {
                                beforeEach(function () {
                                    revert = 0;
                                });

                                it('should not work', async function () {
                                    // the outer transaction will succeed
                                    // need to invoke directly

                                    const data = walletutils.txData(
                                        revert,
                                        wallet.address,
                                        web3.utils.toWei("0", 'kwei'),
                                        setRecoveryAddressData(adminPublicKey)
                                    );

                                    // verify event has 'success' = false
                                    // get hash
                                    const operationHash = utils.getSha3ForConfirmationTx(
                                        wallet.address,
                                        nonce,
                                        adminPublicKey,
                                        data
                                    );

                                    const sig1 = ethUtils.ecsign(operationHash, adminPrivateKey, walletutils.CHAIN_ID);
                                    const r = '0x' + sig1.r.toString('hex');
                                    const s = '0x' + sig1.s.toString('hex');
                                    const v = '0x' + Buffer.from([sig1.v]).toString('hex');

                                    // call invoke1CosignerSends
                                    const result = await wallet.invoke1CosignerSends(
                                        v, r, s,
                                        nonce,
                                        adminPublicKey,
                                        '0x' + data.toString('hex'),
                                        { from: cosignerPublicKey }
                                    );

                                    result.logs[0].args["numOperations"].should.eql(web3.utils.toBN(1));
                                    result.logs[0].args["hash"].should.eql('0x' + operationHash.toString('hex'));
                                    //0x0000000000000000000000000000000000000000000000000000000000000001
                                    result.logs[0].args["result"].should.eql(web3.utils.toBN(1));

                                    // but it should have no effect
                                    const rc = await wallet.recoveryAddress.call();
                                    rc.should.eql(masterPublicKey);
                                });
                            });

                            describe('with revert = 1', function () {
                                beforeEach(function () {
                                    revert = 1;
                                });

                                it('should not work', async function () {

                                    await utils.expectThrow(
                                        walletutils.transact1(
                                            walletutils.txData(
                                                revert,
                                                wallet.address,
                                                web3.utils.toWei("0", 'kwei'),
                                                setRecoveryAddressData(adminPublicKey)
                                            ),
                                            wallet,
                                            nonce,
                                            { address1: adminPublicKey, private1: adminPrivateKey },
                                            cosignerPublicKey
                                        ));

                                    // it should have no effect
                                    const rc = await wallet.recoveryAddress.call();
                                    rc.should.eql(masterPublicKey);
                                });
                            });
                        });

                        describe('emergency recovery performed', function () {

                            const newAdminPublicKey = accounts[6];
                            const newAdminPrivateKey = privateKeys[6];
                            let curAuthVersion;

                            beforeEach(async function () {
                                // call emergencyRecovery with right recovery address
                                // keep same cosigner for now, makes no difference really

                                // must call with recovery address
                                curAuthVersion = await wallet.authVersion.call();

                                const res = await wallet.emergencyRecovery(newAdminPublicKey, fullCosignerKey, { from: masterPublicKey });
                                console.log('emergencyRecovery gas used: ' + res.receipt.gasUsed);
                            });

                            it('should be able to perform transactions with backup key', async function () {
                                // send eth
                                const ethRecipient = utils.newKeyPair().address;
                                await walletutils.transact1(walletutils.txData(
                                    1, // revert (stricter)
                                    ethRecipient,
                                    web3.utils.toWei("1", 'kwei'),
                                    Buffer.from('')
                                ), wallet, nonce,
                                    { address1: newAdminPublicKey, private1: newAdminPrivateKey },
                                    cosignerPublicKey
                                );
                                // const newBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                const newBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                newBalance.should.eql(web3.utils.toBN(web3.utils.toWei("1", 'kwei')));
                            });

                            it('should not be able to perform transactions with old key', async function () {
                                await utils.expectThrow(
                                    walletutils.transact1(walletutils.txData(
                                        0, // even if no revert 
                                        utils.newKeyPair().address,
                                        web3.utils.toWei("1", 'kwei'),
                                        Buffer.from('')
                                    ), wallet, nonce,
                                        { address1: adminPublicKey, private1: adminPrivateKey },
                                        cosignerPublicKey
                                    ));
                            });

                            it('should see that the auth version has incremented', async function () {
                                const newAuthVersion = await wallet.authVersion.call();
                                const authVersionIncrementor = await wallet.AUTH_VERSION_INCREMENTOR.call();
                                const res = curAuthVersion.add(authVersionIncrementor);
                                newAuthVersion.eq(res).should.eql(true);
                            });

                            it('should list only backup key as child key', async function () {

                                const newAuthVersion = await wallet.authVersion.call();
                                const addr = newAuthVersion.add(web3.utils.toBN(newAdminPublicKey));
                                const csk = await wallet.authorizations.call('0x' + utils.numToBuffer(addr).toString('hex'));
                                // //console.log(csk);
                                // verify that the address part is the same
                                utils.asAddressString(csk).should.eql(cosignerPublicKey);
                                csk.eq(fullCosignerKey).should.eql(true);

                                const oldaddr = newAuthVersion.add(web3.utils.toBN(adminPublicKey));
                                const zero = await wallet.authorizations.call('0x' + utils.numToBuffer(oldaddr).toString('hex'));
                                // //console.log(csk);
                                utils.asAddressString(zero).should.eql(zeroAddress);
                            });

                            it('should be able to set a new recovery address', async function () {
                                const newRecoveryAddress = utils.newKeyPair().address;

                                const res = await walletutils.transact1(
                                    walletutils.txData(
                                        1, // stricter
                                        wallet.address,
                                        web3.utils.toWei("0", 'wei'),
                                        setRecoveryAddressData(newRecoveryAddress)
                                    ),
                                    wallet,
                                    nonce,
                                    { address1: newAdminPublicKey, private1: newAdminPrivateKey },
                                    cosignerPublicKey
                                );
                                console.log('setRecoveryAddress gas cost: ' + res);
                                const fromwallet = await wallet.recoveryAddress.call();
                                fromwallet.should.eql(newRecoveryAddress);
                            });

                            it('should be able to recover gas for previous version', async function () {
                                // call recover gas
                                // anyone can call recover gas
                                //function recoverGas(uint256 _version, address[] _keys)

                                const res = await wallet.recoverGas(1, [adminPublicKey]);
                                //res.should.be.less
                                // 15569
                                console.log('recoverGas gas used: ' + res.receipt.gasUsed);
                                //TODO
                            });

                            it('should be able to to add a new key', async function () {
                                // must invoke
                                const newKeyPair = utils.newKeyPair();
                                const newCosigner = accounts[4];
                                await walletutils.transact1(
                                    walletutils.txData(
                                        1, //stricter
                                        wallet.address,
                                        web3.utils.toWei("0", 'kwei'),
                                        setAuthorizedData(newKeyPair.address, newCosigner)
                                    ),
                                    wallet,
                                    nonce,
                                    { address1: newAdminPublicKey, private1: newAdminPrivateKey },
                                    cosignerPublicKey
                                );
                            });

                            describe('should not be able to set the recovery address to an authorized address', function () {
                                let revert;

                                describe('when revert = 0', function () {
                                    beforeEach(function () {
                                        revert = 0;
                                    });

                                    it('should not work', async function () {
                                        // the outer transaction will succeed
                                        const data = walletutils.txData(
                                            revert, // no revert
                                            wallet.address,
                                            web3.utils.toWei("0", 'kwei'),
                                            setRecoveryAddressData(newAdminPublicKey)
                                        );

                                        // get hash
                                        const operationHash = utils.getSha3ForConfirmationTx(
                                            wallet.address,
                                            nonce,
                                            newAdminPublicKey,
                                            data
                                        );

                                        const sig1 = ethUtils.ecsign(operationHash, newAdminPrivateKey, walletutils.CHAIN_ID);
                                        const r = '0x' + sig1.r.toString('hex');
                                        const s = '0x' + sig1.s.toString('hex');
                                        const v = '0x' + Buffer.from([sig1.v]).toString('hex');

                                        // call invoke1CosignerSends
                                        const result = await wallet.invoke1CosignerSends(
                                            v, r, s,
                                            nonce,
                                            newAdminPublicKey,
                                            '0x' + data.toString('hex'),
                                            { from: cosignerPublicKey }
                                        );

                                        // verify event has 'success' = false
                                        result.logs[0].args["numOperations"].should.eql(web3.utils.toBN(1));
                                        result.logs[0].args["hash"].should.eql('0x' + operationHash.toString('hex'));
                                        result.logs[0].args["result"].should.eql(web3.utils.toBN(1));

                                        // verify nothing has changed
                                        const rc = await wallet.recoveryAddress.call();
                                        rc.should.eql(masterPublicKey);
                                    });
                                });
                                describe('when revert = 1', function () {
                                    beforeEach(function () {
                                        revert = 1;
                                    });

                                    it('should not work', async function () {

                                        await utils.expectThrow(
                                            walletutils.transact1(
                                                walletutils.txData(
                                                    revert, // no revert
                                                    wallet.address,
                                                    web3.utils.toWei("0", 'kwei'),
                                                    setRecoveryAddressData(newAdminPublicKey)
                                                ),
                                                wallet,
                                                nonce,
                                                { address1: newAdminPublicKey, private1: newAdminPrivateKey },
                                                cosignerPublicKey
                                            )
                                        );

                                        // verify nothing has changed
                                        const rc = await wallet.recoveryAddress.call();
                                        rc.should.eql(masterPublicKey);
                                    });
                                });
                            });

                            it('should not be able to set the recovery address to an authorized address', async function () {

                            });

                            describe('new key added', function () {

                                const newKeyPair = utils.newKeyPair();
                                const newCosigner = accounts[4];

                                beforeEach(async function () {
                                    // add new key
                                    await walletutils.transact1(
                                        walletutils.txData(
                                            1, // stricter
                                            wallet.address,
                                            web3.utils.toWei("0", 'kwei'),
                                            setAuthorizedData(newKeyPair.address, newCosigner)
                                        ),
                                        wallet,
                                        nonce,
                                        { address1: newAdminPublicKey, private1: newAdminPrivateKey },
                                        cosignerPublicKey
                                    );
                                    nonce += 1;
                                });
                            });

                        });

                        it('should not be able to recover the gas for an invalid version', async function () {
                            // 
                            await utils.expectThrow(
                                wallet.recoverGas(0, [adminPublicKey])
                            );
                        });

                        describe('`setRecoveryAddress` called', function () {
                            const newRecoveryAddress = utils.newKeyPair().address;

                            beforeEach(async function () {
                                // call setRecoveryAddress
                                const gas = await walletutils.transact1(
                                    walletutils.txData(
                                        1, // stricter
                                        wallet.address,
                                        web3.utils.toWei("0", 'kwei'),
                                        setRecoveryAddressData(newRecoveryAddress)
                                    ), wallet,
                                    nonce,
                                    { address1: adminPublicKey, private1: adminPrivateKey },
                                    cosignerPublicKey
                                );

                                console.log('setRecoveryAddress gas used: ' + gas);
                            });

                            it('should not be able to do a recovery with the old recovery address', async function () {
                                await utils.expectThrow(
                                    wallet.emergencyRecovery(utils.newKeyPair().address, utils.newKeyPair().address, { from: masterPublicKey })
                                );
                            });

                            it.skip('should be able to do a recovery with the new recovery address', async function () {
                                // send eth to new key
                                await wallet.emergencyRecovery(utils.newKeyPair().address, utils.newKeyPair().address, { from: newRecoveryAddress });
                                //console.log('emergencyRecovery gas used: ' + res.receipt.gasUsed);

                            });
                        });

                    });

                    describe('concerning device keys', function () {

                        it('should not be able to call `setAuthorized` directly', async function () {
                            // 
                            await utils.expectThrow(
                                wallet.setAuthorized(utils.newKeyPair().address, utils.newKeyPair().address)
                            );
                        });

                        it('should not be able to call `setAuthorized` with 0 key', async function () {
                            // this will pass, but fail internally 
                            const data = walletutils.txData(
                                0, // no revert
                                wallet.address,
                                web3.utils.toWei("0", 'kwei'),
                                setAuthorizedData('0x0', utils.newKeyPair().address)
                            );

                            // verify event has 'success' = false
                            // get hash
                            const operationHash = utils.getSha3ForConfirmationTx(
                                wallet.address,
                                nonce,
                                adminPublicKey,
                                data
                            );

                            const sig1 = ethUtils.ecsign(operationHash, adminPrivateKey, walletutils.CHAIN_ID);
                            const r = '0x' + sig1.r.toString('hex');
                            const s = '0x' + sig1.s.toString('hex');
                            const v = '0x' + Buffer.from([sig1.v]).toString('hex');

                            // call invoke1CosignerSends
                            const result = await wallet.invoke1CosignerSends(
                                v, r, s,
                                nonce,
                                adminPublicKey,
                                '0x' + data.toString('hex'),
                                { from: cosignerPublicKey }
                            );

                            result.logs[0].args["numOperations"].should.eql(web3.utils.toBN(1));
                            result.logs[0].args["hash"].should.eql('0x' + operationHash.toString('hex'));
                            result.logs[0].args["result"].should.eql(web3.utils.toBN(1));

                            nonce += 1

                            // try with revert == 1
                            await utils.expectThrow(
                                walletutils.transact1(
                                    walletutils.txData(
                                        1, // revert
                                        wallet.address,
                                        web3.utils.toWei("0", 'kwei'),
                                        setAuthorizedData('0x0', utils.newKeyPair().address)
                                    ),
                                    wallet,
                                    nonce,
                                    { address1: adminPublicKey, private1: adminPrivateKey },
                                    cosignerPublicKey
                                )
                            );
                        });

                        it.skip("should not be able to remove a key that doesn't exist", async function () {
                            // currently possible
                        });

                        describe('authVersion received', function () {
                            let authVersion;
                            beforeEach(async function () {
                                // const authVersionIncrementor = await wallet.AUTH_VERSION_INCREMENTOR.call();
                                //10000000000000000000000000000000000000000  40 0s is right
                                //console.log("authVersionIncrementor: " + authVersionIncrementor.toString(16));
                                authVersion = await wallet.authVersion.call();
                                //console.log('authVersion: ' + authVersion.toString(16));
                            });

                            // setAuthorized - add key
                            describe('new key added with out a cosigner', function () {

                                const newKeyPair = { address: accounts[3], private: privateKeys[3] };
                                const newCosigner = newKeyPair.address;
                                const newCosignerFull = web3.utils.toBN(newCosigner).add(metaData);

                                beforeEach(async function () {

                                    const gas = await walletutils.transact1(
                                        walletutils.txData(
                                            1,
                                            wallet.address,
                                            web3.utils.toWei("0", 'kwei'),
                                            setAuthorizedData(newKeyPair.address, newCosignerFull)
                                        ),
                                        wallet,
                                        nonce,
                                        { address1: adminPublicKey, private1: adminPrivateKey },
                                        cosignerPublicKey
                                    );

                                    console.log('setAuthorized gas used: ' + gas);

                                    // we used a nonce here, we need to increment it
                                    nonce += 1;
                                });

                                it('should see that the new key exists', async function () {

                                    const addr = authVersion.add(web3.utils.toBN(newKeyPair.address));
                                    const csk = await wallet.authorizations.call('0x' + utils.numToBuffer(addr).toString('hex'));
                                    //console.log(csk);
                                    utils.asAddressString(csk).should.eql(newCosigner);
                                    csk.eq(newCosignerFull).should.eql(true);
                                });

                                it('should be able to use new key to perform transactions with revert = 0', async function () {
                                    const ethRecipient = utils.newKeyPair().address;
                                    const ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                    const transferAmount = web3.utils.toWei("1", 'wei');

                                    await walletutils.transact0(
                                        walletutils.txData(0, ethRecipient, transferAmount, Buffer.from('')),
                                        wallet,
                                        newKeyPair.address);

                                    checkBalances(
                                        transferAmount,
                                        fundAmount,
                                        wallet.address,
                                        ethRecipient,
                                        ethRecipientOrigBalance
                                    );
                                });

                                it('should be able to use new key to perform transactions with revert = 1', async function () {
                                    const ethRecipient = utils.newKeyPair().address;
                                    const ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                    const transferAmount = web3.utils.toWei("1", 'wei');

                                    await walletutils.transact0(
                                        walletutils.txData(1, ethRecipient, transferAmount, Buffer.from('')),
                                        wallet,
                                        newKeyPair.address);

                                    checkBalances(
                                        transferAmount,
                                        fundAmount,
                                        wallet.address,
                                        ethRecipient,
                                        ethRecipientOrigBalance
                                    );
                                });

                                it('should be able to use the old key to perform transactions with revert = 1', async function () {
                                    // send eth somewhere
                                    const ethRecipient = utils.newKeyPair().address;
                                    const ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                    const transferAmount = web3.utils.toWei("1", 'wei');

                                    await walletutils.transact1(
                                        walletutils.txData(1, ethRecipient, transferAmount, Buffer.from('')),
                                        wallet,
                                        nonce,
                                        { address1: adminPublicKey, private1: adminPrivateKey },
                                        cosignerPublicKey
                                    );

                                    checkBalances(
                                        transferAmount,
                                        fundAmount,
                                        wallet.address,
                                        ethRecipient,
                                        ethRecipientOrigBalance
                                    );
                                });

                                it('should be able to use the old key to perform transactions with revert = 0', async function () {
                                    // send eth somewhere
                                    const ethRecipient = utils.newKeyPair().address;
                                    const ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                    const transferAmount = web3.utils.toWei("1", 'wei');

                                    await walletutils.transact1(
                                        walletutils.txData(0, ethRecipient, transferAmount, Buffer.from('')),
                                        wallet,
                                        nonce,
                                        { address1: adminPublicKey, private1: adminPrivateKey },
                                        cosignerPublicKey
                                    );

                                    checkBalances(
                                        transferAmount,
                                        fundAmount,
                                        wallet.address,
                                        ethRecipient,
                                        ethRecipientOrigBalance
                                    );
                                });

                                describe('removing keys', function () {
                                    beforeEach(async function () {
                                        // remove key
                                        // have to do it through invoke
                                        var dataArr = [];
                                        // function signature
                                        dataArr.push(utils.funcHash(SET_AUTHORIZED_SIGNATURE));
                                        // arg: authorized addr
                                        dataArr.push(utils.numToBuffer(newKeyPair.address));
                                        // arg: cosigner addr (set to 0 removes the key)
                                        dataArr.push(utils.numToBuffer(0));

                                        await walletutils.transact1(
                                            walletutils.txData(
                                                1,
                                                wallet.address,
                                                web3.utils.toWei("0", 'kwei'),
                                                Buffer.concat(dataArr)),
                                            wallet,
                                            nonce,
                                            { address1: adminPublicKey, private1: adminPrivateKey },
                                            cosignerPublicKey);

                                        nonce += 1
                                    });

                                    it('should see that the new key does not exist', async function () {
                                        // manually call the authorization mapping
                                        const addr = authVersion.add(web3.utils.toBN(newKeyPair.address));
                                        const csk = await wallet.authorizations.call('0x' + utils.numToBuffer(addr).toString('hex'));
                                        utils.asAddressString(csk).should.eql(zeroAddress);
                                    });

                                    it('should not be able to use the key we just removed', async function () {
                                        const ethRecipient = utils.newKeyPair().address;
                                        //const ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                        const transferAmount = web3.utils.toWei("1", 'wei');

                                        await utils.expectThrow(
                                            walletutils.transact0(
                                                walletutils.txData(0, ethRecipient, transferAmount, Buffer.from('')),
                                                wallet,
                                                newKeyPair.address)
                                        );

                                    });

                                });

                            });

                            describe('new key added with a cosigner', function () {

                                const newKeyPair = utils.newKeyPair();
                                // has to be an address that truffle knows
                                const newCosigner = accounts[4];
                                const newCosignerFull = web3.utils.toBN(newCosigner).add(metaData);

                                beforeEach(async function () {
                                    // add a key
                                    // have to do it through invoke
                                    var dataArr = [];
                                    // function signature
                                    dataArr.push(utils.funcHash(SET_AUTHORIZED_SIGNATURE));
                                    // arg: authorized addr
                                    dataArr.push(utils.numToBuffer(newKeyPair.address));
                                    // arg: cosigner addr
                                    dataArr.push(utils.numToBuffer(newCosignerFull));

                                    const gas = await walletutils.transact1(
                                        walletutils.txData(
                                            1,
                                            wallet.address,
                                            web3.utils.toWei("0", 'kwei'),
                                            Buffer.concat(dataArr)),
                                        wallet,
                                        nonce,
                                        { address1: adminPublicKey, private1: adminPrivateKey },
                                        cosignerPublicKey);
                                    console.log('setAuthorized gas used: ' + gas);

                                    // we used a nonce here, so we need to increment
                                    nonce += 1
                                });

                                it('should see that the new key exists', async function () {
                                    // manually call the authorization mapping
                                    const addr = authVersion.add(web3.utils.toBN(newKeyPair.address));
                                    //console.log("addr: " + addr.toString(16));
                                    const csk = await wallet.authorizations.call('0x' + utils.numToBuffer(addr).toString('hex'));
                                    utils.asAddressString(csk).should.eql(newCosigner);
                                    csk.eq(newCosignerFull).should.eql(true);
                                });

                                it('should be able to use new key to perform transactions with revert = 1', async function () {
                                    const ethRecipient = utils.newKeyPair().address;
                                    const ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                    const transferAmount = web3.utils.toWei("1", 'wei');

                                    const newNonce = await walletutils.getNonce(wallet, newKeyPair.address);

                                    await walletutils.transact1(
                                        walletutils.txData(1, ethRecipient, transferAmount, Buffer.from('')),
                                        wallet,
                                        newNonce,
                                        { address1: newKeyPair.address, private1: newKeyPair.private },
                                        newCosigner
                                    );

                                    checkBalances(
                                        transferAmount,
                                        fundAmount,
                                        wallet.address,
                                        ethRecipient,
                                        ethRecipientOrigBalance
                                    );
                                });

                                it('should be able to use new key to perform transactions with revert = 0', async function () {
                                    const ethRecipient = utils.newKeyPair().address;
                                    const ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                    const transferAmount = web3.utils.toWei("1", 'wei');

                                    const newNonce = await walletutils.getNonce(wallet, newKeyPair.address);

                                    await walletutils.transact1(
                                        walletutils.txData(0, ethRecipient, transferAmount, Buffer.from('')),
                                        wallet,
                                        newNonce,
                                        { address1: newKeyPair.address, private1: newKeyPair.private },
                                        newCosigner
                                    );

                                    checkBalances(
                                        transferAmount,
                                        fundAmount,
                                        wallet.address,
                                        ethRecipient,
                                        ethRecipientOrigBalance
                                    );
                                });


                                it('should be able to use the old key to perform transactions with revert = 1', async function () {
                                    // send eth somewhere
                                    const ethRecipient = utils.newKeyPair().address;
                                    const ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                    const transferAmount = web3.utils.toWei("1", 'wei');

                                    await walletutils.transact1(
                                        walletutils.txData(1, ethRecipient, transferAmount, Buffer.from('')),
                                        wallet,
                                        nonce,
                                        { address1: adminPublicKey, private1: adminPrivateKey },
                                        cosignerPublicKey
                                    );

                                    checkBalances(
                                        transferAmount,
                                        fundAmount,
                                        wallet.address,
                                        ethRecipient,
                                        ethRecipientOrigBalance
                                    );
                                });


                                it('should be able to use the old key to perform transactions with revert = 0', async function () {
                                    // send eth somewhere
                                    const ethRecipient = utils.newKeyPair().address;
                                    const ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                    const transferAmount = web3.utils.toWei("1", 'wei');

                                    await walletutils.transact1(
                                        walletutils.txData(0, ethRecipient, transferAmount, Buffer.from('')),
                                        wallet,
                                        nonce,
                                        { address1: adminPublicKey, private1: adminPrivateKey },
                                        cosignerPublicKey
                                    );

                                    checkBalances(
                                        transferAmount,
                                        fundAmount,
                                        wallet.address,
                                        ethRecipient,
                                        ethRecipientOrigBalance
                                    );
                                });

                                describe('removing keys', function () {
                                    beforeEach(async function () {
                                        // remove key
                                        // have to do it through invoke
                                        var dataArr = [];
                                        // function signature
                                        dataArr.push(utils.funcHash(SET_AUTHORIZED_SIGNATURE));
                                        // arg: authorized addr
                                        dataArr.push(utils.numToBuffer(newKeyPair.address));
                                        // arg: cosigner addr (set to 0 removes the key)
                                        dataArr.push(utils.numToBuffer(0));

                                        await walletutils.transact1(
                                            walletutils.txData(
                                                1,
                                                wallet.address,
                                                web3.utils.toWei("0", 'kwei'),
                                                Buffer.concat(dataArr)),
                                            wallet,
                                            nonce,
                                            { address1: adminPublicKey, private1: adminPrivateKey },
                                            cosignerPublicKey);

                                        nonce += 1
                                    });


                                    it('should see that the new key does not exist', async function () {
                                        // manually call the authorization mapping
                                        const addr = authVersion.add(web3.utils.toBN(newKeyPair.address));
                                        const csk = (await wallet.authorizations.call('0x' + utils.numToBuffer(addr).toString('hex')));
                                        utils.asAddressString(csk).should.eql(zeroAddress);
                                    });

                                    it('should not be able to use the key we just removed', async function () {
                                        // 
                                        const ethRecipient = utils.newKeyPair().address;
                                        //const ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                        const transferAmount = web3.utils.toWei("1", 'wei');

                                        await utils.expectThrow(
                                            walletutils.transact1(
                                                walletutils.txData(0, ethRecipient, transferAmount, Buffer.from('')),
                                                wallet,
                                                nonce,
                                                { address1: newKeyPair.address, private1: newKeyPair.private },
                                                newCosigner
                                            )
                                        );

                                    });

                                });

                            });

                            // setAuthorized - remove key
                            describe('removing keys', function () {
                                it.skip('should not be able to remove your only key', async function () {
                                    // currently possible
                                });
                            });
                            //
                        });



                    });

                    describe('when sending eth via admin key', function () {

                        let ethRecipient;
                        const transferAmount = web3.utils.toWei("10000", 'wei');
                        //console.log(transferAmount);

                        describe('to account address', function () {

                            beforeEach(function () {
                                ethRecipient = accounts[3];
                            });

                            it('should revert if v is inappropriate for cosigner as msg.sender', async function () {
                                // will revert, and nothing will have changed
                                const ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                const data = walletutils.txData(0, ethRecipient, transferAmount, Buffer.from(''));
                                // get hash
                                const operationHash = utils.getSha3ForConfirmationTx(
                                    wallet.address,
                                    nonce,
                                    adminPublicKey,
                                    data
                                );

                                const sig1 = ethUtils.ecsign(operationHash, adminPrivateKey, walletutils.CHAIN_ID);
                                const r = '0x' + sig1.r.toString('hex');
                                const s = '0x' + sig1.s.toString('hex');
                                const v = '0x' + Buffer.from([sig1.v + 9]).toString('hex');

                                console.log("v: " + v);

                                // call invoke1CosignerSends
                                await utils.expectThrow(
                                    wallet.invoke1CosignerSends(
                                        v, r, s,
                                        nonce,
                                        adminPublicKey,
                                        '0x' + data.toString('hex'),
                                        { from: cosignerPublicKey }
                                    ));

                                const ethRecipientNewBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                ethRecipientOrigBalance.should.eql(ethRecipientNewBalance);
                            });

                            it('should revert if wrong nonce is used', async function () {
                                const ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                await utils.expectThrow(
                                    walletutils.transact1Twice(
                                        walletutils.txData(0, ethRecipient, transferAmount, Buffer.from('')),
                                        wallet,
                                        255,
                                        { address1: adminPublicKey, private1: adminPrivateKey },
                                        cosignerPublicKey
                                    ));

                                await utils.expectThrow(
                                    walletutils.transact1Twice(
                                        walletutils.txData(0, ethRecipient, transferAmount, Buffer.from('')),
                                        wallet,
                                        nonce + 1,
                                        { address1: adminPublicKey, private1: adminPrivateKey },
                                        cosignerPublicKey
                                    ));

                                const newBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                newBalance.should.eql(ethRecipientOrigBalance);
                            });

                            describe('after sending eth with cosigner as msg.sender with revert = 1', function () {
                                let ethRecipientOrigBalance;

                                beforeEach(async function () {

                                    ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));

                                    const signer = cosignerPublicKey;
                                    const gas = await walletutils.transact1Twice(
                                        walletutils.txData(1, ethRecipient, transferAmount, Buffer.from('')),
                                        wallet,
                                        nonce,
                                        { address1: adminPublicKey, private1: adminPrivateKey },
                                        signer
                                    );

                                    logGasPrice(wtype, INVOKE1, TRANSFER_ETH, gas);
                                });

                                it('should report proper balances', async function () {
                                    checkBalances(
                                        transferAmount * 2,
                                        fundAmount,
                                        wallet.address,
                                        ethRecipient,
                                        ethRecipientOrigBalance
                                    );
                                });
                            });

                            describe('after sending eth with cosigner as msg.sender with revert = 0', function () {
                                let ethRecipientOrigBalance;

                                beforeEach(async function () {

                                    ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));

                                    const signer = cosignerPublicKey;
                                    const gas = await walletutils.transact1Twice(
                                        walletutils.txData(0, ethRecipient, transferAmount, Buffer.from('')),
                                        wallet,
                                        nonce,
                                        { address1: adminPublicKey, private1: adminPrivateKey },
                                        signer
                                    );

                                    logGasPrice(wtype, INVOKE1, TRANSFER_ETH, gas);
                                });

                                it('should report proper balances', async function () {
                                    checkBalances(
                                        transferAmount * 2,
                                        fundAmount,
                                        wallet.address,
                                        ethRecipient,
                                        ethRecipientOrigBalance
                                    );
                                });
                            });

                            describe('after sending eth with signer as msg.sender and cosigner as passed in sig with revert = 1', function () {
                                let ethRecipientOrigBalance;

                                beforeEach(async function () {

                                    ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));

                                    const gas = await walletutils.transact11Twice(
                                        walletutils.txData(
                                            1,
                                            ethRecipient,
                                            transferAmount,
                                            Buffer.from('')
                                        ),
                                        wallet,
                                        nonce,
                                        { address1: cosignerPublicKey, private1: cosignerPrivateKey },
                                        adminPublicKey
                                    );

                                    logGasPrice(wtype, INVOKE11, TRANSFER_ETH, gas);
                                });

                                it('should report proper balances', async function () {
                                    checkBalances(
                                        //transferAmount.mul(2),
                                        transferAmount * 2,
                                        fundAmount,
                                        wallet.address,
                                        ethRecipient,
                                        ethRecipientOrigBalance
                                    );
                                });
                            });

                            describe('after sending eth with signer as msg.sender and cosigner as passed in sig with revert = 0', function () {
                                let ethRecipientOrigBalance;

                                beforeEach(async function () {

                                    ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));

                                    const gas = await walletutils.transact11Twice(
                                        walletutils.txData(
                                            0,
                                            ethRecipient,
                                            transferAmount,
                                            Buffer.from('')
                                        ),
                                        wallet,
                                        nonce,
                                        { address1: cosignerPublicKey, private1: cosignerPrivateKey },
                                        adminPublicKey
                                    );

                                    logGasPrice(wtype, INVOKE11, TRANSFER_ETH, gas);
                                });

                                it('should report proper balances', async function () {
                                    checkBalances(
                                        //transferAmount.mul(2),
                                        transferAmount * 2,
                                        fundAmount,
                                        wallet.address,
                                        ethRecipient,
                                        ethRecipientOrigBalance
                                    );
                                });
                            });

                            it('should revert if v is inappropriate for signer as msg.sender and cosigner as passed in sig', async function () {
                                // will revert, and nothing will have changed
                                const ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));

                                const data = walletutils.txData(0, ethRecipient, transferAmount, Buffer.from(''));
                                // get hash
                                const operationHash = utils.getSha3ForConfirmationTx(
                                    wallet.address,
                                    nonce,
                                    adminPublicKey,
                                    data
                                );

                                const sig1 = ethUtils.ecsign(operationHash, cosignerPrivateKey, walletutils.CHAIN_ID);
                                const r = '0x' + sig1.r.toString('hex');
                                const s = '0x' + sig1.s.toString('hex');
                                const v = '0x' + Buffer.from([sig1.v + 9]).toString('hex');

                                console.log("v: " + v);

                                // call invoke1SignerSends
                                await utils.expectThrow(
                                    wallet.invoke1SignerSends(
                                        v, r, s,
                                        '0x' + data.toString('hex'),
                                        { from: adminPublicKey }
                                    ));

                                const ethRecipientNewBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                ethRecipientOrigBalance.should.eql(ethRecipientNewBalance);
                            });

                            describe('after sending eth via second signature with revert = 0', function () {
                                let ethRecipientOrigBalance;

                                beforeEach(async function () {

                                    ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));

                                    const signer = accounts[2];

                                    const gas = await walletutils.transact2Twice(
                                        walletutils.txData(
                                            0,
                                            ethRecipient,
                                            transferAmount,
                                            Buffer.from('')
                                        ),
                                        wallet,
                                        nonce,
                                        {
                                            address1: adminPublicKey,
                                            private1: adminPrivateKey,
                                            address2: cosignerPublicKey,
                                            private2: cosignerPrivateKey
                                        },
                                        signer
                                    );

                                    logGasPrice(wtype, INVOKE2, TRANSFER_ETH, gas);
                                });

                                it('should report proper balances', async function () {
                                    checkBalances(
                                        //transferAmount.mul(2),
                                        transferAmount * 2,
                                        fundAmount,
                                        wallet.address,
                                        ethRecipient,
                                        ethRecipientOrigBalance
                                    );
                                });
                            });

                            describe('after another key has been added to the wallet with same cosigner', function () {
                                const newKeyPair = utils.newKeyPair();

                                beforeEach(async function () {
                                    // add another key to the wallet so that the nonces are the same
                                    await walletutils.transact1(
                                        walletutils.txData(
                                            1, //stricter
                                            wallet.address,
                                            web3.utils.toWei("0", 'kwei'),
                                            setAuthorizedData(newKeyPair.address, cosignerPublicKey)
                                        ),
                                        wallet,
                                        nonce,
                                        { address1: adminPublicKey, private1: adminPrivateKey },
                                        cosignerPublicKey
                                    );

                                    nonce += 1;
                                });

                                describe('after sending eth to an address via second signature', function () {

                                    let ethRecipientOrigBalance;

                                    let sig1;
                                    let sig2;

                                    beforeEach(async function () {
                                        // do invoke2 with original key
                                        ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));

                                        const signer = accounts[2];

                                        const data = walletutils.txData(
                                            0,
                                            ethRecipient,
                                            transferAmount,
                                            Buffer.from('')
                                        );
                                        // get hash
                                        const operationHash = utils.getSha3ForConfirmationTx(
                                            wallet.address,
                                            nonce,
                                            adminPublicKey,
                                            data
                                        );

                                        //console.log("operationHash: 0x" + operationHash.toString('hex'));

                                        sig1 = ethUtils.ecsign(operationHash, adminPrivateKey, walletutils.CHAIN_ID);
                                        sig2 = ethUtils.ecsign(operationHash, cosignerPrivateKey, walletutils.CHAIN_ID);
                                        const [r, s, v] = utils.splitSignatures(sig1, sig2);

                                        await wallet.invoke2(
                                            v, r, s,
                                            nonce,
                                            adminPublicKey,
                                            '0x' + data.toString('hex'),
                                            { from: signer }
                                        );
                                    });

                                    it('should report proper balances', async function () {
                                        checkBalances(
                                            transferAmount,
                                            fundAmount,
                                            wallet.address,
                                            ethRecipient,
                                            ethRecipientOrigBalance
                                        );
                                    });

                                    it('should not be able to replay the cosigner signatures', async function () {
                                        // use the same signature from the cosigner for the first transaction
                                        // to authorize the second one.

                                        // because we incremented the nonce of the first key with the addition of the new key
                                        // via setAuthorized, we need to perform a transaction with the new key
                                        // in order to get its nonce to 1 as well
                                        const signer = accounts[2];

                                        const data = walletutils.txData(
                                            0,
                                            ethRecipient,
                                            transferAmount,
                                            Buffer.from('')
                                        );

                                        // get new key nonce up to 1
                                        {
                                            // get hash
                                            const operationHash = utils.getSha3ForConfirmationTx(
                                                wallet.address,
                                                0,
                                                newKeyPair.address,
                                                data
                                            );

                                            //console.log("operationHash: 0x" + operationHash.toString('hex'));

                                            const new_sig1 = ethUtils.ecsign(operationHash, newKeyPair.private, walletutils.CHAIN_ID);
                                            const new_sig2 = ethUtils.ecsign(operationHash, cosignerPrivateKey, walletutils.CHAIN_ID);
                                            const [new_r, new_s, new_v] = utils.splitSignatures(new_sig1, new_sig2);

                                            await wallet.invoke2(
                                                new_v, new_r, new_s,
                                                0,
                                                newKeyPair.address,
                                                '0x' + data.toString('hex'),
                                                { from: signer }
                                            );
                                        }

                                        // get hash with same nonce (1) as other key
                                        const operationHash = utils.getSha3ForConfirmationTx(
                                            wallet.address,
                                            nonce,
                                            newKeyPair.address,
                                            data
                                        );

                                        sig1 = ethUtils.ecsign(operationHash, newKeyPair.private, walletutils.CHAIN_ID);
                                        // attempt to use sig2 from previous transaction
                                        const [r, s, v] = utils.splitSignatures(sig1, sig2);

                                        // expect throw here (hashes will not match)
                                        await utils.expectThrow(
                                            wallet.invoke2(
                                                v, r, s,
                                                nonce,
                                                newKeyPair.address,
                                                '0x' + data.toString('hex'),
                                                { from: signer }
                                            )
                                        );
                                    });
                                });
                            });

                            describe('after sending eth via second signature with revert = 1', function () {
                                let ethRecipientOrigBalance;

                                beforeEach(async function () {

                                    ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));

                                    const signer = accounts[2];

                                    const gas = await walletutils.transact2Twice(
                                        walletutils.txData(
                                            1,
                                            ethRecipient,
                                            transferAmount,
                                            Buffer.from('')
                                        ),
                                        wallet,
                                        nonce,
                                        {
                                            address1: adminPublicKey,
                                            private1: adminPrivateKey,
                                            address2: cosignerPublicKey,
                                            private2: cosignerPrivateKey
                                        },
                                        signer
                                    );

                                    logGasPrice(wtype, INVOKE2, TRANSFER_ETH, gas);
                                });

                                it('should report proper balances', async function () {
                                    checkBalances(
                                        //transferAmount.mul(2),
                                        transferAmount * 2,
                                        fundAmount,
                                        wallet.address,
                                        ethRecipient,
                                        ethRecipientOrigBalance
                                    );
                                });
                            });

                            it('should revert if v is inappropriate for second signature', async function () {
                                // will revert, and nothing will have changed
                                const ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));

                                const data = walletutils.txData(0, ethRecipient, transferAmount, Buffer.from(''));

                                const signer = accounts[2];

                                // get hash
                                const operationHash = utils.getSha3ForConfirmationTx(
                                    wallet.address,
                                    nonce,
                                    adminPublicKey,
                                    data
                                );

                                let r, s, v;
                                const sig1 = ethUtils.ecsign(operationHash, adminPrivateKey, walletutils.CHAIN_ID);
                                const sig2 = ethUtils.ecsign(operationHash, cosignerPrivateKey, walletutils.CHAIN_ID);
                                [r, s, v] = utils.splitSignatures(sig1, sig2);
                                // oh javascript
                                v[0] += 4
                                v[1] += 19

                                await utils.expectThrow(
                                    wallet.invoke2(
                                        v, r, s,
                                        nonce,
                                        adminPublicKey,
                                        '0x' + data.toString('hex'),
                                        { from: signer }
                                    ));

                                const ethRecipientNewBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                ethRecipientOrigBalance.should.eql(ethRecipientNewBalance);
                            });
                        });

                        describe('to contract that throws upon receiving Ξ', function () {

                            let otherContract;

                            beforeEach(async function () {
                                // setup other contract
                                otherContract = await ThrowOnPayable.new({ from: accounts[3] });

                                ethRecipient = otherContract.address;
                            });

                            describe('after sending eth with revert = 0', function () {
                                let ethRecipientOrigBalance;
                                let walletOriginalBalance;

                                beforeEach(async function () {
                                    // get balances
                                    ethRecipientOrigBalance = await web3.eth.getBalance(ethRecipient);
                                    walletOriginalBalance = await web3.eth.getBalance(wallet.address);

                                    const data = walletutils.txData(
                                        0,
                                        ethRecipient,
                                        transferAmount,
                                        Buffer.from('')
                                    );

                                    // must sign with child key
                                    const operationHash = utils.getSha3ForConfirmationTx(
                                        wallet.address,
                                        nonce,
                                        adminPublicKey,
                                        data
                                    );

                                    //console.log("operationHash: 0x" + operationHash.toString('hex'));

                                    const sig = ethUtils.ecsign(operationHash, adminPrivateKey, walletutils.CHAIN_ID);
                                    const r = '0x' + sig.r.toString('hex');
                                    const s = '0x' + sig.s.toString('hex');
                                    const v = '0x' + Buffer.from([sig.v]).toString('hex');

                                    // console.log("r: " + r);
                                    // console.log("s: " + s);
                                    // console.log("v: " + v);

                                    const send = async function () {

                                        await wallet.invoke1CosignerSends(
                                            v, r, s,
                                            nonce,
                                            adminPublicKey,
                                            '0x' + data.toString('hex'),
                                            { from: cosignerPublicKey }
                                        );
                                    };

                                    // no longer expecting a throw here
                                    // await utils.expectThrow(
                                    await send();
                                    // );

                                });

                                it('should be the case that nothing has changed', async function () {
                                    // left in wallet
                                    (await web3.eth.getBalance(wallet.address)).should.eql(walletOriginalBalance);
                                    // recipientAmount
                                    (await web3.eth.getBalance(ethRecipient)).should.eql(ethRecipientOrigBalance);
                                });
                            });

                            describe('after sending eth with revert = 1', function () {
                                let ethRecipientOrigBalance;
                                let walletOriginalBalance;

                                beforeEach(async function () {
                                    // get balances
                                    ethRecipientOrigBalance = await web3.eth.getBalance(ethRecipient);
                                    walletOriginalBalance = await web3.eth.getBalance(wallet.address);

                                    const data = walletutils.txData(
                                        1,
                                        ethRecipient,
                                        transferAmount,
                                        Buffer.from('')
                                    );

                                    // must sign with child key
                                    const operationHash = utils.getSha3ForConfirmationTx(
                                        wallet.address,
                                        nonce,
                                        adminPublicKey,
                                        data
                                    );

                                    //console.log("operationHash: 0x" + operationHash.toString('hex'));

                                    const sig = ethUtils.ecsign(operationHash, adminPrivateKey, walletutils.CHAIN_ID);
                                    const r = '0x' + sig.r.toString('hex');
                                    const s = '0x' + sig.s.toString('hex');
                                    const v = '0x' + Buffer.from([sig.v]).toString('hex');

                                    const send = async function () {

                                        await wallet.invoke1CosignerSends(
                                            v, r, s,
                                            nonce,
                                            adminPublicKey,
                                            '0x' + data.toString('hex'),
                                            { from: cosignerPublicKey }
                                        );
                                    };

                                    // expect a throw here
                                    await utils.expectThrow(
                                        send()
                                    );

                                });

                                it('should be the case that nothing has changed', async function () {
                                    // left in wallet
                                    (await web3.eth.getBalance(wallet.address)).should.eql(walletOriginalBalance);
                                    // recipientAmount
                                    const recipAmt = (await web3.eth.getBalance(ethRecipient));
                                    // receiver amount
                                    recipAmt.should.eql(ethRecipientOrigBalance);
                                });
                            });
                        });

                        describe("to a contract that doesn't throw upon receiving Ξ", function () {

                            let otherContract;

                            beforeEach(async function () {
                                // setup other contract
                                otherContract = await SimpleWallet.new({ from: accounts[3] });

                                ethRecipient = otherContract.address;
                            });

                            describe('after sending eth with revert = 0', function () {
                                let ethRecipientOrigBalance;
                                let walletOriginalBalance;

                                beforeEach(async function () {
                                    // get balances
                                    ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                    walletOriginalBalance = web3.utils.toBN(await web3.eth.getBalance(wallet.address));
                                    const signer = cosignerPublicKey;

                                    await walletutils.transact1(
                                        walletutils.txData(
                                            0,
                                            ethRecipient,
                                            transferAmount,
                                            Buffer.from('')
                                        ),
                                        wallet,
                                        nonce,
                                        { address1: adminPublicKey, private1: adminPrivateKey },
                                        signer
                                    );
                                });

                                it('should show proper balances', async function () {
                                    const remaining = walletOriginalBalance.sub(web3.utils.toBN(transferAmount));
                                    // left in wallet
                                    web3.utils.toBN(await web3.eth.getBalance(wallet.address)).eq(remaining).should.eql(true);
                                    // recipientAmount
                                    const recipAmt = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                    // receiver amount
                                    recipAmt.eq(web3.utils.toBN(transferAmount).add(ethRecipientOrigBalance)).should.eql(true);
                                });

                            });


                            describe('after sending eth with revert = 1', function () {
                                // HERE
                                let ethRecipientOrigBalance;
                                let walletOriginalBalance;

                                beforeEach(async function () {
                                    // get balances
                                    ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                    walletOriginalBalance = web3.utils.toBN(await web3.eth.getBalance(wallet.address));
                                    const signer = cosignerPublicKey;

                                    await walletutils.transact1(
                                        walletutils.txData(
                                            1,
                                            ethRecipient,
                                            transferAmount,
                                            Buffer.from('')
                                        ),
                                        wallet,
                                        nonce,
                                        { address1: adminPublicKey, private1: adminPrivateKey },
                                        signer
                                    );
                                });

                                it('should show proper balances', async function () {
                                    const remaining = walletOriginalBalance.sub(web3.utils.toBN(transferAmount));
                                    // left in wallet
                                    web3.utils.toBN(await web3.eth.getBalance(wallet.address)).eq(remaining).should.eql(true);
                                    // recipientAmount
                                    const recipAmt = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                    // receiver amount
                                    recipAmt.eq(web3.utils.toBN(transferAmount).add(ethRecipientOrigBalance)).should.eql(true);
                                });

                            });

                            describe("concerning 0 ETH transfers", function () {
                                it("should be able to send 0 ETH to the wallet from another contract", async function () {
                                    // send wallet 0 eth
                                    // via transfer
                                    await otherContract.transferOut(wallet.address, { value: 0, from: accounts[3] });
                                    // via send
                                    await otherContract.sendOut(wallet.address, { value: 0, from: accounts[3] })
                                });
                            });
                        });

                        describe("to another copy of our wallet", function () {

                            let otherContract;

                            beforeEach(async function () {

                                let newsalt = salt;
                                // setup other contract
                                if (wtype == walletutils.WALLET_CLONE_2) {
                                    // clone 2 address will hash to the same
                                    // as the salt is the same and the code
                                    // is the same and doesn't include 
                                    // the constructor parameters
                                    // so we need a new salt here
                                    newsalt = '0x' + crypto.randomBytes(32).toString('hex');
                                }
                                otherContract = await walletutils.createWallet(
                                    wtype,
                                    accounts[0],
                                    accounts[1],
                                    accounts[1],
                                    _walletFactory,
                                    newsalt
                                );

                                ethRecipient = otherContract.address;
                            });

                            describe('after sending eth with revert = 1', function () {
                                let ethRecipientOrigBalance;
                                let walletOriginalBalance;

                                beforeEach(async function () {
                                    // get balances
                                    ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                    walletOriginalBalance = web3.utils.toBN(await web3.eth.getBalance(wallet.address));

                                    await walletutils.transact1(
                                        walletutils.txData(
                                            1,
                                            ethRecipient,
                                            transferAmount,
                                            Buffer.from('')
                                        ),
                                        wallet,
                                        nonce,
                                        { address1: adminPublicKey, private1: adminPrivateKey },
                                        cosignerPublicKey
                                    );
                                });

                                it('should show proper balances', async function () {
                                    const remaining = walletOriginalBalance.sub(web3.utils.toBN(transferAmount));
                                    // left in wallet
                                    web3.utils.toBN(await web3.eth.getBalance(wallet.address)).eq(remaining).should.eql(true);
                                    // recipientAmount
                                    const recipAmt = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                    // receiver amount
                                    recipAmt.eq(web3.utils.toBN(transferAmount).add(ethRecipientOrigBalance)).should.eql(true);
                                });

                            });

                            describe('after sending eth with revert = 0', function () {
                                let ethRecipientOrigBalance;
                                let walletOriginalBalance;

                                beforeEach(async function () {
                                    // get balances
                                    ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                    walletOriginalBalance = web3.utils.toBN(await web3.eth.getBalance(wallet.address));

                                    await walletutils.transact1(
                                        walletutils.txData(
                                            0,
                                            ethRecipient,
                                            transferAmount,
                                            Buffer.from('')
                                        ),
                                        wallet,
                                        nonce,
                                        { address1: adminPublicKey, private1: adminPrivateKey },
                                        cosignerPublicKey
                                    );
                                });

                                it('should show proper balances', async function () {
                                    const remaining = walletOriginalBalance.sub(web3.utils.toBN(transferAmount));
                                    // left in wallet
                                    web3.utils.toBN(await web3.eth.getBalance(wallet.address)).eq(remaining).should.eql(true);
                                    // recipientAmount
                                    const recipAmt = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                    // receiver amount
                                    recipAmt.eq(web3.utils.toBN(transferAmount).add(ethRecipientOrigBalance)).should.eql(true);
                                });

                            });

                        });
                    });

                    describe('with regards to erc20 tokens', function () {
                        const erc20Owner = accounts[1];
                        const anotherAccount = accounts[2];
                        const totalSupply = 100
                        let token;

                        describe('when the erc20 token contract is created', function () {

                            beforeEach(async function () {
                                token = await StandardTokenMock.new(erc20Owner, totalSupply);
                            });

                            // basic tests to verify the contracts working
                            describe('when asked for the total token supply', function () {

                                it('returns the total amount of tokens', async function () {
                                    const total = await token.totalSupply();
                                    assert.equal(totalSupply, total);
                                });
                            });

                            describe('when asked for the balanceOf', function () {

                                describe('when the requested account has no tokens', function () {
                                    it('returns zero', async function () {
                                        const balance = await token.balanceOf(anotherAccount);
                                        assert.equal(balance, 0);
                                    });
                                });

                                describe('when the requested account has some tokens', function () {
                                    it('returns the total amount of tokens', async function () {
                                        const balance = await token.balanceOf(erc20Owner);
                                        assert.equal(balance, totalSupply);
                                    });
                                });
                            });

                            // transfer some to contract owner
                            describe('when the contract owner owns erc20 tokens', function () {
                                const amount = totalSupply / 2; //50

                                beforeEach(async function () {
                                    await token.transfer(wallet.address, amount, { from: erc20Owner });

                                    const senderBalance = await token.balanceOf(erc20Owner);
                                    assert.equal(senderBalance, totalSupply - amount);

                                    const recipientBalance = await token.balanceOf(wallet.address);
                                    assert.equal(recipientBalance, amount);
                                });

                                describe('when the requested account has some tokens', function () {
                                    it('returns the total amount of tokens', async function () {
                                        const balance = await token.balanceOf(wallet.address);
                                        assert.equal(balance, amount);
                                    });
                                });

                                describe('when the contract owner transfers erc20 tokens', function () {

                                    const erc20Recipient = accounts[3];

                                    describe('when providing invalid data.length', function () {

                                        it('should revert', async function () {
                                            // 
                                            let dataArr = [];
                                            let revert = Buffer.alloc(1);
                                            // don't revert for now
                                            revert.writeUInt8(0);
                                            dataArr.push(revert);
                                            // 'to' is not padded (20 bytes)
                                            dataArr.push(Buffer.from(token.address.replace('0x', ''), 'hex')); // address as string
                                            // value (32 bytes)
                                            dataArr.push(utils.numToBuffer(web3.utils.toWei("1", 'wei')));
                                            // data length (0) (this is intentionally wrong)
                                            dataArr.push(utils.numToBuffer(1));
                                            // function signature
                                            dataArr.push(utils.funcHash('transfer(address,uint256)'));
                                            // arg: to address
                                            dataArr.push(utils.numToBuffer(erc20Recipient));
                                            // arg: amount (256)
                                            dataArr.push(utils.numToBuffer(amount));

                                            await utils.expectThrow(
                                                walletutils.transact1(
                                                    Buffer.concat(dataArr),
                                                    wallet,
                                                    nonce,
                                                    { address1: adminPublicKey, private1: adminPrivateKey },
                                                    cosignerPublicKey
                                                )
                                            );
                                        });
                                    });

                                    describe('via cosigner as second signature', function () {

                                        beforeEach(async function () {

                                            const signer = accounts[2];

                                            const gas = await walletutils.transact2Twice(
                                                walletutils.txData(
                                                    1,
                                                    token.address,
                                                    web3.utils.toWei("0", 'kwei'),
                                                    walletutils.erc20Transfer(amount / 2, erc20Recipient)
                                                ),
                                                wallet,
                                                nonce,
                                                {
                                                    address1: adminPublicKey,
                                                    private1: adminPrivateKey,
                                                    address2: cosignerPublicKey,
                                                    private2: cosignerPrivateKey
                                                },
                                                signer
                                            );

                                            logGasPrice(wtype, INVOKE2, TRANSFER_ERC20, gas);
                                        });

                                        it('should report correct erc20 token and Ξ balances', async function () {

                                            // check the token balances
                                            const senderBalance = await token.balanceOf(erc20Owner);
                                            assert.equal(senderBalance, totalSupply - amount);

                                            const contractBalance = await token.balanceOf(wallet.address);
                                            //console.log(contractBalance.toString(10)); // 0x32
                                            assert.equal(contractBalance, 0);

                                            const recipientBalance = await token.balanceOf(erc20Recipient);
                                            //console.log(recipientBalance.toString(10)); // 0x32
                                            assert.equal(recipientBalance, amount);

                                            // check eth balances to be sure no weirdness happened
                                            let erc20RecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(erc20Recipient));

                                            checkBalances(
                                                0,
                                                fundAmount,
                                                wallet.address,
                                                erc20Recipient,
                                                erc20RecipientOrigBalance
                                            );
                                        });
                                    });

                                    describe('via cosigner as msg.sender', function () {

                                        beforeEach(async function () {

                                            const gas = await walletutils.transact1Twice(
                                                walletutils.txData(
                                                    1,
                                                    token.address,
                                                    web3.utils.toWei("0", 'kwei'),
                                                    walletutils.erc20Transfer(amount / 2, erc20Recipient)
                                                ),
                                                wallet,
                                                nonce,
                                                { address1: adminPublicKey, private1: adminPrivateKey },
                                                cosignerPublicKey
                                            );

                                            logGasPrice(wtype, INVOKE1, TRANSFER_ERC20, gas);
                                        });

                                        it('should report correct erc20 token and Ξ balances', async function () {

                                            // check the token balances
                                            const senderBalance = await token.balanceOf(erc20Owner);
                                            assert.equal(senderBalance, totalSupply - amount);

                                            const contractBalance = await token.balanceOf(wallet.address);
                                            //console.log(contractBalance.toString(10)); // 0x32
                                            assert.equal(contractBalance, 0);

                                            const recipientBalance = await token.balanceOf(erc20Recipient);
                                            //console.log(recipientBalance.toString(10)); // 0x32
                                            assert.equal(recipientBalance, amount);

                                            // check eth balances to be sure no weirdness happened
                                            let erc20RecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(erc20Recipient));

                                            checkBalances(
                                                0,
                                                fundAmount,
                                                wallet.address,
                                                erc20Recipient,
                                                erc20RecipientOrigBalance
                                            );
                                        });
                                    });

                                    describe('via signer as msg.sender and cosigner as passed in sig', function () {

                                        beforeEach(async function () {

                                            const gas = await walletutils.transact11Twice(
                                                walletutils.txData(
                                                    1,
                                                    token.address,
                                                    web3.utils.toWei("0", 'kwei'),
                                                    walletutils.erc20Transfer(amount / 2, erc20Recipient)
                                                ),
                                                wallet,
                                                nonce,
                                                { address1: cosignerPublicKey, private1: cosignerPrivateKey },
                                                adminPublicKey
                                            );

                                            logGasPrice(wtype, INVOKE11, TRANSFER_ERC20, gas);
                                        });

                                        it('should report correct erc20 token and Ξ balances', async function () {

                                            // check the token balances
                                            const senderBalance = await token.balanceOf(erc20Owner);
                                            assert.equal(senderBalance, totalSupply - amount);

                                            const contractBalance = await token.balanceOf(wallet.address);
                                            //console.log(contractBalance.toString(10)); // 0x32
                                            assert.equal(contractBalance, 0);

                                            const recipientBalance = await token.balanceOf(erc20Recipient);
                                            //console.log(recipientBalance.toString(10)); // 0x32
                                            assert.equal(recipientBalance, amount);

                                            // check eth balances to be sure no weirdness happened
                                            let erc20RecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(erc20Recipient));

                                            checkBalances(
                                                0,
                                                fundAmount,
                                                wallet.address,
                                                erc20Recipient,
                                                erc20RecipientOrigBalance
                                            );
                                        });
                                    });
                                });
                            });
                        });
                    });

                    describe('with regards to erc721', function () {
                        const name = 'Non Fungible Token';
                        const symbol = 'NFT';
                        const firstTokenId = 100;
                        const secondTokenId = 200;
                        const creator = accounts[0];
                        let token;

                        beforeEach(async function () {
                            token = await ERC721TokenMock.new(name, symbol, { from: creator });
                            await token.mint(creator, firstTokenId, { from: creator });
                            await token.mint(creator, secondTokenId, { from: creator });
                        });


                        describe('totalSupply', function () {
                            it('returns total token supply', async function () {
                                const totalSupply = await token.totalSupply();
                                totalSupply.should.eql(web3.utils.toBN(2));
                            });
                        });

                        describe('balanceOf', function () {
                            describe('when the given address owns some tokens', function () {
                                it('returns the amount of tokens owned by the given address', async function () {
                                    const balance = await token.balanceOf(creator);
                                    balance.should.eql(web3.utils.toBN(2));
                                });
                            });

                            describe('when the given address does not own any tokens', function () {
                                it('returns 0', async function () {
                                    let balance = await token.balanceOf(accounts[1]);
                                    balance.should.eql(web3.utils.toBN(0));

                                    balance = await token.balanceOf(wallet.address);
                                    balance.should.eql(web3.utils.toBN(0));
                                });
                            });
                        });

                        describe('when the contract owner owns an erc721 token', function () {

                            beforeEach(async function () {
                                // send to contract owner
                                await token.transferFrom(creator, wallet.address, firstTokenId, { from: creator });
                                await token.transferFrom(creator, wallet.address, secondTokenId, { from: creator });
                            });

                            it('should say we own the token', async function () {

                                let newOwner = await token.ownerOf(firstTokenId);
                                newOwner.should.be.equal(wallet.address);

                                newOwner = await token.ownerOf(secondTokenId);
                                newOwner.should.be.equal(wallet.address);

                                const newOwnerBalance = await token.balanceOf(wallet.address);
                                newOwnerBalance.should.eql(web3.utils.toBN(2));

                                const previousOwnerBalance = await token.balanceOf(creator);
                                previousOwnerBalance.should.eql(web3.utils.toBN(0));
                            });

                            describe('when wallet transfers the token using transferFrom()', function () {

                                const recipient = utils.newKeyPair().address;

                                describe('via second signature', function () {
                                    beforeEach(async function () {

                                        const signer = accounts[2];

                                        await walletutils.transact2(
                                            walletutils.txData(
                                                1,
                                                token.address,
                                                web3.utils.toWei("0", 'kwei'),
                                                walletutils.erc721Transfer(firstTokenId, wallet.address, recipient),
                                            ),
                                            wallet,
                                            nonce,
                                            {
                                                address1: adminPublicKey,
                                                private1: adminPrivateKey,
                                                address2: cosignerPublicKey,
                                                private2: cosignerPrivateKey
                                            },
                                            signer
                                        );

                                        const gas = await walletutils.transact2(
                                            walletutils.txData(
                                                1,
                                                token.address,
                                                web3.utils.toWei("0", 'kwei'),
                                                walletutils.erc721Transfer(secondTokenId, wallet.address, recipient),
                                            ),
                                            wallet,
                                            nonce + 1,
                                            {
                                                address1: adminPublicKey,
                                                private1: adminPrivateKey,
                                                address2: cosignerPublicKey,
                                                private2: cosignerPrivateKey
                                            },
                                            signer
                                        );

                                        logGasPrice(wtype, INVOKE2, TRANSFER_ERC721, gas);
                                    });

                                    it('should say the new owner owns the token', async function () {

                                        let newOwner = await token.ownerOf(firstTokenId);
                                        newOwner.should.be.equal(recipient);

                                        newOwner = await token.ownerOf(secondTokenId);
                                        newOwner.should.be.equal(recipient);

                                        const newOwnerBalance = await token.balanceOf(recipient);
                                        newOwnerBalance.should.eql(web3.utils.toBN(2));

                                        const previousOwnerBalance = await token.balanceOf(wallet.address);
                                        previousOwnerBalance.should.eql(web3.utils.toBN(0));

                                        // check eth balances to be sure no weirdness happened
                                        let erc721RecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(recipient));

                                        checkBalances(
                                            0,
                                            fundAmount,
                                            wallet.address,
                                            recipient,
                                            erc721RecipientOrigBalance
                                        );
                                    });
                                });

                                describe('via cosigner as msg.sender', function () {
                                    beforeEach(async function () {

                                        await walletutils.transact1(
                                            walletutils.txData(
                                                1,
                                                token.address,
                                                web3.utils.toWei("0", 'kwei'),
                                                walletutils.erc721Transfer(firstTokenId, wallet.address, recipient)
                                            ),
                                            wallet,
                                            nonce,
                                            { address1: adminPublicKey, private1: adminPrivateKey },
                                            cosignerPublicKey
                                        );

                                        const gas = await walletutils.transact1(
                                            walletutils.txData(
                                                1,
                                                token.address,
                                                web3.utils.toWei("0", 'kwei'),
                                                walletutils.erc721Transfer(secondTokenId, wallet.address, recipient)
                                            ),
                                            wallet,
                                            nonce + 1,
                                            { address1: adminPublicKey, private1: adminPrivateKey },
                                            cosignerPublicKey
                                        );

                                        logGasPrice(wtype, INVOKE1, TRANSFER_ERC721, gas);
                                    });

                                    it('should say the new owner owns the token', async function () {

                                        let newOwner = await token.ownerOf(firstTokenId);
                                        newOwner.should.be.equal(recipient);

                                        newOwner = await token.ownerOf(secondTokenId);
                                        newOwner.should.be.equal(recipient);

                                        const newOwnerBalance = await token.balanceOf(recipient);
                                        newOwnerBalance.should.eql(web3.utils.toBN(2));

                                        const previousOwnerBalance = await token.balanceOf(wallet.address);
                                        previousOwnerBalance.should.eql(web3.utils.toBN(0));

                                        // check eth balances to be sure no weirdness happened
                                        let erc721RecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(recipient));

                                        checkBalances(
                                            0,
                                            fundAmount,
                                            wallet.address,
                                            recipient,
                                            erc721RecipientOrigBalance
                                        );
                                    });
                                });

                                describe('via signer as msg.sender and cosigner as passed in sig', function () {
                                    beforeEach(async function () {

                                        await walletutils.transact1(
                                            walletutils.txData(
                                                1,
                                                token.address,
                                                web3.utils.toWei("0", 'kwei'),
                                                walletutils.erc721Transfer(firstTokenId, wallet.address, recipient)
                                            ),
                                            wallet,
                                            nonce,
                                            { address1: adminPublicKey, private1: adminPrivateKey },
                                            cosignerPublicKey
                                        );

                                        const gas = await walletutils.transact11(
                                            walletutils.txData(
                                                1,
                                                token.address,
                                                web3.utils.toWei("0", 'kwei'),
                                                walletutils.erc721Transfer(secondTokenId, wallet.address, recipient)
                                            ),
                                            wallet,
                                            nonce + 1,
                                            { address1: cosignerPublicKey, private1: cosignerPrivateKey },
                                            adminPublicKey
                                        );

                                        logGasPrice(wtype, INVOKE11, TRANSFER_ERC721, gas);
                                    });

                                    it('should say the new owner owns the token', async function () {

                                        let newOwner = await token.ownerOf(firstTokenId);
                                        newOwner.should.be.equal(recipient);

                                        newOwner = await token.ownerOf(secondTokenId);
                                        newOwner.should.be.equal(recipient);

                                        const newOwnerBalance = await token.balanceOf(recipient);
                                        newOwnerBalance.should.eql(web3.utils.toBN(2));

                                        const previousOwnerBalance = await token.balanceOf(wallet.address);
                                        previousOwnerBalance.should.eql(web3.utils.toBN(0));

                                        // check eth balances to be sure no weirdness happened
                                        let erc721RecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(recipient));

                                        checkBalances(
                                            0,
                                            fundAmount,
                                            wallet.address,
                                            recipient,
                                            erc721RecipientOrigBalance
                                        );
                                    });
                                });

                            });
                        });
                    });

                    describe('with regards to multisend', function () {
                        // ETH

                        // ERC20 tokens
                        const erc20Owner = accounts[1];
                        const anotherAccount = accounts[2];
                        const totalSupply = 100
                        let erc20Token;

                        // ERC721 tokens
                        const name = 'Non Fungible Token 2';
                        const symbol = 'NFT 2';
                        const firstTokenId = 100;
                        const secondTokenId = 200;
                        const creator = accounts[0];
                        let erc721Token;

                        describe('when the contracts have been created', function () {
                            beforeEach(async function () {
                                // erc 20
                                erc20Token = await StandardTokenMock.new(erc20Owner, totalSupply);

                                // erc 721
                                erc721Token = await ERC721TokenMock.new(name, symbol, { from: creator });
                                await erc721Token.mint(creator, firstTokenId, { from: creator });
                                await erc721Token.mint(creator, secondTokenId, { from: creator });
                            });

                            // basic tests to verify the contracts working
                            describe('erc20 tokens', function () {

                                describe('when asked for the total erc20 token supply', function () {

                                    it('returns the total amount of tokens', async function () {
                                        const total = await erc20Token.totalSupply();
                                        assert.equal(totalSupply, total);
                                    });
                                });

                                describe('when asked for the balanceOf', function () {

                                    describe('when the requested account has no tokens', function () {
                                        it('returns zero', async function () {
                                            const balance = await erc20Token.balanceOf(anotherAccount);
                                            assert.equal(balance, 0);
                                        });
                                    });

                                    describe('when the requested account has some tokens', function () {
                                        it('returns the total amount of tokens', async function () {
                                            const balance = await erc20Token.balanceOf(erc20Owner);
                                            assert.equal(balance, 100);
                                        });
                                    });
                                });
                            });

                            describe('erc721 tokens', function () {
                                describe('totalSupply', function () {
                                    it('returns total erc721 token supply', async function () {
                                        const totalSupply = await erc721Token.totalSupply();
                                        totalSupply.should.eql(web3.utils.toBN(2));
                                    });
                                });

                                describe('balanceOf', function () {
                                    describe('when the given address owns some erc721 tokens', function () {
                                        it('returns the amount of erc721 tokens owned by the given address', async function () {
                                            const balance = await erc721Token.balanceOf(creator);
                                            balance.should.eql(web3.utils.toBN(2));
                                        });
                                    });

                                    describe('when the given address does not own any erc721 tokens', function () {
                                        it('returns 0', async function () {
                                            let balance = await erc721Token.balanceOf(accounts[1]);
                                            balance.should.eql(web3.utils.toBN(0));

                                            balance = await erc721Token.balanceOf(wallet.address);
                                            balance.should.eql(web3.utils.toBN(0));
                                        });
                                    });
                                });
                            });

                            // ownership
                            // transfer some to contract owner
                            describe('when the contract owner owns erc20 & erc721 tokens', function () {
                                const amount = totalSupply / 2; //50

                                beforeEach(async function () {
                                    // erc 20 tokens
                                    await erc20Token.transfer(wallet.address, amount, { from: erc20Owner });

                                    const senderBalance = await erc20Token.balanceOf(erc20Owner);
                                    assert.equal(senderBalance, totalSupply - amount);

                                    const recipientBalance = await erc20Token.balanceOf(wallet.address);
                                    assert.equal(recipientBalance, amount);

                                    // erc 721 token
                                    await erc721Token.transferFrom(creator, wallet.address, firstTokenId, { from: creator });
                                });

                                describe('when the requested account has some erc20 tokens', function () {
                                    it('returns the total amount of erc20 tokens', async function () {
                                        const balance = await erc20Token.balanceOf(wallet.address);
                                        assert.equal(balance, amount);
                                    });
                                });

                                it('should say we own the erc721 token', async function () {

                                    const newOwner = await erc721Token.ownerOf(firstTokenId);
                                    newOwner.should.be.equal(wallet.address);

                                    const newOwnerBalance = await erc721Token.balanceOf(wallet.address);
                                    newOwnerBalance.should.eql(web3.utils.toBN(1));

                                    const previousOwnerBalance = await erc721Token.balanceOf(creator);
                                    previousOwnerBalance.should.eql(web3.utils.toBN(1));
                                });

                                // do ETH, ERC20 and ERC721 transfer in one TX!
                                describe('when the contract owner transfers Ξ, erc20 and erc721 tokens via multisend msg.sender cosigner with revert = 0', function () {

                                    const erc20Recipient = accounts[3];
                                    const erc721Recipient = accounts[4];
                                    const ethRecipient = utils.newKeyPair().address;
                                    let ethRecipientOrigBalance;
                                    const transferAmount = web3.utils.toWei("10000", 'wei');

                                    beforeEach(async function () {

                                        ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));

                                        // to (20), value (32), data length (32), data
                                        let dataArr = [];
                                        let revert = Buffer.alloc(1);
                                        // revert
                                        revert.writeUInt8(0);
                                        dataArr.push(revert);

                                        // transfer ETH
                                        // 'to' is not padded (20 bytes)
                                        dataArr.push(Buffer.from(ethRecipient.replace('0x', ''), 'hex')); // address as string
                                        // value (32 bytes)
                                        dataArr.push(utils.numToBuffer(transferAmount));
                                        //console.log("transferAmount: " + utils.numToBuffer(transferAmount).toString('hex'));
                                        // data length (0)
                                        dataArr.push(utils.numToBuffer(0));
                                        // transfer ERC20
                                        // to
                                        dataArr.push(Buffer.from(erc20Token.address.replace('0x', ''), 'hex')); // address as string
                                        // value (32 bytes)
                                        dataArr.push(utils.numToBuffer(0));
                                        // push data length
                                        const erc20Buff = walletutils.erc20Transfer(amount / 2, erc20Recipient);
                                        dataArr.push(utils.numToBuffer(erc20Buff.length))
                                        // push data
                                        dataArr.push(erc20Buff);

                                        // transfer kitty to random addr
                                        // data argument
                                        dataArr.push(Buffer.from(erc721Token.address.replace('0x', ''), 'hex')); // address as string
                                        // value (32 bytes)
                                        dataArr.push(utils.numToBuffer(0));
                                        // create 721 data
                                        const erc721DataBuff = walletutils.erc721Transfer(firstTokenId, wallet.address, erc721Recipient);
                                        dataArr.push(utils.numToBuffer(erc721DataBuff.length));
                                        dataArr.push(erc721DataBuff);
                                        // concat all buffers
                                        //console.log('data: 0x' + Buffer.concat(dataArr).toString('hex'));

                                        const gas = await walletutils.transact1(
                                            Buffer.concat(dataArr),
                                            wallet,
                                            nonce,
                                            { address1: adminPublicKey, private1: adminPrivateKey },
                                            cosignerPublicKey
                                        );

                                        logGasPrice(wtype, INVOKE1, TRANSFER_MULTI, gas);
                                    });

                                    // Multisend
                                    it('should report correct erc20 and erc721 token and Ξ balances', async function () {

                                        // check ETH balances
                                        checkBalances(
                                            transferAmount,
                                            fundAmount,
                                            wallet.address,
                                            ethRecipient,
                                            ethRecipientOrigBalance
                                        );

                                        // check the ERC20 token balances
                                        const senderBalance = await erc20Token.balanceOf(erc20Owner);
                                        assert.equal(senderBalance, totalSupply - amount);

                                        const contractBalance = await erc20Token.balanceOf(wallet.address);
                                        //console.log(contractBalance);
                                        assert.equal(contractBalance, amount / 2);

                                        const recipientBalance = await erc20Token.balanceOf(erc20Recipient);
                                        assert.equal(recipientBalance, amount / 2);

                                        // check eth balances to be sure no weirdness happened
                                        let erc20RecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(erc20Recipient));

                                        let tBig = web3.utils.toBN(transferAmount);
                                        let remaining = (web3.utils.toBN(fundAmount)).sub(tBig);
                                        // left in wallet
                                        web3.utils.toBN(await web3.eth.getBalance(wallet.address)).eq(remaining).should.eql(true);
                                        // recipientAmount
                                        let recipAmt = web3.utils.toBN(await web3.eth.getBalance(erc20Recipient));
                                        // receiver amount
                                        recipAmt.eq(erc20RecipientOrigBalance).should.eql(true);

                                        // ERC721
                                        const newOwner = await erc721Token.ownerOf(firstTokenId);
                                        newOwner.should.be.equal(erc721Recipient);

                                        const newOwnerBalance = await erc721Token.balanceOf(erc721Recipient);
                                        newOwnerBalance.eq(web3.utils.toBN("1")).should.eql(true);

                                        const previousOwnerBalance = await erc721Token.balanceOf(wallet.address);
                                        previousOwnerBalance.eq(web3.utils.toBN("0")).should.eql(true);

                                        // check eth balances to be sure no weirdness happened
                                        let erc721RecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(erc721Recipient));

                                        tBig = web3.utils.toBN(transferAmount);
                                        remaining = (web3.utils.toBN(fundAmount)).sub(tBig);
                                        // left in wallet
                                        web3.utils.toBN(await web3.eth.getBalance(wallet.address)).eq(remaining).should.eql(true);
                                        // recipientAmount
                                        recipAmt = web3.utils.toBN(await web3.eth.getBalance(erc721Recipient));
                                        // receiver amount
                                        recipAmt.should.eql(erc721RecipientOrigBalance);
                                    });
                                });

                                describe('when the contract owner transfers Ξ, erc20 and erc721 tokens via multisend msg.sender signer, passed in sig for cosigner with revert = 1', function () {

                                    const erc20Recipient = accounts[3];
                                    const erc721Recipient = accounts[4];
                                    const ethRecipient = utils.newKeyPair().address;
                                    let ethRecipientOrigBalance;
                                    const transferAmount = web3.utils.toWei("10000", 'wei');

                                    beforeEach(async function () {

                                        ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));

                                        // to (20), value (32), data length (32), data
                                        let dataArr = [];
                                        let revertBuff = Buffer.alloc(1);
                                        // stricter
                                        revertBuff.writeUInt8(1);
                                        dataArr.push(revertBuff);

                                        // transfer ETH
                                        // 'to' is not padded (20 bytes)
                                        dataArr.push(Buffer.from(ethRecipient.replace('0x', ''), 'hex')); // address as string
                                        // value (32 bytes)
                                        dataArr.push(utils.numToBuffer(transferAmount));
                                        //console.log("transferAmount: " + utils.numToBuffer(transferAmount).toString('hex'));
                                        // data length (0)
                                        dataArr.push(utils.numToBuffer(0));
                                        // transfer ERC20
                                        // to
                                        dataArr.push(Buffer.from(erc20Token.address.replace('0x', ''), 'hex')); // address as string
                                        // value (32 bytes)
                                        dataArr.push(utils.numToBuffer(0));
                                        // data
                                        // push data length
                                        const erc20Buff = walletutils.erc20Transfer(amount / 2, erc20Recipient);
                                        dataArr.push(utils.numToBuffer(erc20Buff.length))
                                        // push data
                                        dataArr.push(erc20Buff);

                                        // transfer kitty to random addr
                                        // data argument

                                        dataArr.push(Buffer.from(erc721Token.address.replace('0x', ''), 'hex')); // address as string
                                        // value (32 bytes)
                                        dataArr.push(utils.numToBuffer(0));
                                        // erc 721 data
                                        const erc721DataBuff = walletutils.erc721Transfer(firstTokenId, wallet.address, erc721Recipient);
                                        dataArr.push(utils.numToBuffer(erc721DataBuff.length));
                                        dataArr.push(erc721DataBuff);
                                        // concat all buffers
                                        //console.log('data: 0x' + Buffer.concat(dataArr).toString('hex'));

                                        const gas = await walletutils.transact11(
                                            Buffer.concat(dataArr),
                                            wallet,
                                            nonce,
                                            { address1: cosignerPublicKey, private1: cosignerPrivateKey },
                                            adminPublicKey
                                        );

                                        logGasPrice(wtype, INVOKE11, TRANSFER_MULTI, gas);
                                    });

                                    // Multisend
                                    it('should report correct erc20 and erc721 token and Ξ balances', async function () {

                                        // check ETH balances
                                        checkBalances(
                                            transferAmount,
                                            fundAmount,
                                            wallet.address,
                                            ethRecipient,
                                            ethRecipientOrigBalance
                                        );

                                        // check the ERC20 token balances
                                        const senderBalance = await erc20Token.balanceOf(erc20Owner);
                                        assert.equal(senderBalance, totalSupply - amount);

                                        const contractBalance = await erc20Token.balanceOf(wallet.address);
                                        //console.log(contractBalance);
                                        assert.equal(contractBalance, amount / 2);

                                        const recipientBalance = await erc20Token.balanceOf(erc20Recipient);
                                        assert.equal(recipientBalance, amount / 2);

                                        // check eth balances to be sure no weirdness happened
                                        let erc20RecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(erc20Recipient));

                                        let tBig = web3.utils.toBN(transferAmount);
                                        let remaining = (web3.utils.toBN(fundAmount)).sub(tBig);
                                        // left in wallet
                                        web3.utils.toBN(await web3.eth.getBalance(wallet.address)).eq(remaining).should.eql(true);
                                        // recipientAmount
                                        let recipAmt = web3.utils.toBN(await web3.eth.getBalance(erc20Recipient));
                                        // receiver amount
                                        recipAmt.eq(erc20RecipientOrigBalance).should.eql(true);

                                        // ERC721
                                        const newOwner = await erc721Token.ownerOf(firstTokenId);
                                        newOwner.should.be.equal(erc721Recipient);

                                        const newOwnerBalance = await erc721Token.balanceOf(erc721Recipient);
                                        newOwnerBalance.eq(web3.utils.toBN("1")).should.eql(true);

                                        const previousOwnerBalance = await erc721Token.balanceOf(wallet.address);
                                        previousOwnerBalance.eq(web3.utils.toBN("0")).should.eql(true);

                                        // check eth balances to be sure no weirdness happened
                                        let erc721RecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(erc721Recipient));

                                        tBig = web3.utils.toBN(transferAmount);
                                        remaining = (web3.utils.toBN(fundAmount)).sub(tBig);
                                        // left in wallet
                                        web3.utils.toBN(await web3.eth.getBalance(wallet.address)).eq(remaining).should.eql(true);
                                        // recipientAmount
                                        recipAmt = web3.utils.toBN(await web3.eth.getBalance(erc721Recipient));
                                        // receiver amount
                                        recipAmt.eq(erc721RecipientOrigBalance).should.eql(true);
                                    });
                                });

                                describe('when multisend includes a failing transaction', function () {

                                    it('should be the case that the rest go through when revert = 0', async function () {
                                        const erc20Recipient = accounts[3];
                                        const erc721Recipient = accounts[4];
                                        const ethRecipient = utils.newKeyPair().address;
                                        const ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                        const erc20RecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(erc20Recipient));
                                        const erc721RecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(erc721Recipient));
                                        const transferAmount = web3.utils.toWei("10000", 'wei');

                                        // to (20), value (32), data length (32), data
                                        let dataArr = [];
                                        let revertBuff = Buffer.alloc(1);
                                        // no revert
                                        revertBuff.writeUInt8(0);
                                        dataArr.push(revertBuff);

                                        // transfer ETH
                                        // 'to' is not padded (20 bytes)
                                        dataArr.push(Buffer.from(ethRecipient.replace('0x', ''), 'hex')); // address as string
                                        // value (32 bytes)
                                        dataArr.push(utils.numToBuffer(transferAmount));
                                        // data length (0)
                                        dataArr.push(utils.numToBuffer(0));
                                        // transfer ERC20
                                        // to
                                        dataArr.push(Buffer.from(erc20Token.address.replace('0x', ''), 'hex')); // address as string
                                        // value (32 bytes)
                                        dataArr.push(utils.numToBuffer(0));
                                        // push data length (Transfer more than you have)
                                        const erc20Buff = walletutils.erc20Transfer(amount * 1000, erc20Recipient);
                                        dataArr.push(utils.numToBuffer(erc20Buff.length))
                                        // push data
                                        dataArr.push(erc20Buff);

                                        // transfer kitty to random addr
                                        // data argument
                                        dataArr.push(Buffer.from(erc721Token.address.replace('0x', ''), 'hex')); // address as string
                                        // value (32 bytes)
                                        dataArr.push(utils.numToBuffer(0));
                                        // create 721 data
                                        const erc721DataBuff = walletutils.erc721Transfer(firstTokenId, wallet.address, erc721Recipient);
                                        dataArr.push(utils.numToBuffer(erc721DataBuff.length));
                                        dataArr.push(erc721DataBuff);
                                        const data = Buffer.concat(dataArr);

                                        // get hash
                                        const operationHash = utils.getSha3ForConfirmationTx(
                                            wallet.address,
                                            nonce,
                                            adminPublicKey,
                                            data
                                        );

                                        //console.log("operationHash: 0x" + operationHash.toString('hex'));

                                        const sig1 = ethUtils.ecsign(operationHash, adminPrivateKey, walletutils.CHAIN_ID);
                                        const r = '0x' + sig1.r.toString('hex');
                                        const s = '0x' + sig1.s.toString('hex');
                                        const v = '0x' + Buffer.from([sig1.v]).toString('hex');

                                        // call invoke1CosignerSends
                                        const result = await wallet.invoke1CosignerSends(
                                            v, r, s,
                                            nonce,
                                            adminPublicKey,
                                            '0x' + data.toString('hex'),
                                            { from: cosignerPublicKey }
                                        );

                                        result.logs.length.should.eql(1);
                                        result.logs[0].args["result"].should.eql(web3.utils.toBN(2));
                                        result.logs[0].args["numOperations"].should.eql(web3.utils.toBN(3));
                                        result.logs[0].args["hash"].should.eql('0x' + operationHash.toString('hex'));

                                        // check ETH balances
                                        checkBalances(
                                            transferAmount,
                                            fundAmount,
                                            wallet.address,
                                            ethRecipient,
                                            ethRecipientOrigBalance
                                        );

                                        // check the ERC20 token balances
                                        const senderBalance = await erc20Token.balanceOf(erc20Owner);
                                        assert.equal(senderBalance, totalSupply - amount);

                                        const contractBalance = await erc20Token.balanceOf(wallet.address);
                                        assert.equal(contractBalance, amount);

                                        const recipientBalance = await erc20Token.balanceOf(erc20Recipient);
                                        assert.equal(recipientBalance, 0);

                                        // check eth balances to be sure no weirdness happened
                                        let tBig = web3.utils.toBN(transferAmount);
                                        let remaining = (web3.utils.toBN(fundAmount)).sub(tBig);
                                        // left in wallet
                                        web3.utils.toBN(await web3.eth.getBalance(wallet.address)).eq(remaining).should.eql(true);
                                        // recipientAmount
                                        let recipAmt = web3.utils.toBN(await web3.eth.getBalance(erc20Recipient));
                                        // receiver amount
                                        recipAmt.eq(erc20RecipientOrigBalance).should.eql(true);

                                        // ERC721
                                        const newOwner = await erc721Token.ownerOf(firstTokenId);
                                        newOwner.should.be.equal(erc721Recipient);

                                        const newOwnerBalance = await erc721Token.balanceOf(erc721Recipient);
                                        newOwnerBalance.should.eql(web3.utils.toBN(1));

                                        const previousOwnerBalance = await erc721Token.balanceOf(wallet.address);
                                        previousOwnerBalance.should.eql(web3.utils.toBN(0));

                                        // check eth balances to be sure no weirdness happened
                                        tBig = web3.utils.toBN(transferAmount);
                                        remaining = (web3.utils.toBN(fundAmount)).sub(tBig);
                                        // left in wallet
                                        web3.utils.toBN(await web3.eth.getBalance(wallet.address)).eq(remaining).should.eql(true);
                                        // recipientAmount
                                        recipAmt = web3.utils.toBN(await web3.eth.getBalance(erc721Recipient));
                                        // receiver amount
                                        recipAmt.eq(erc721RecipientOrigBalance).should.eql(true);
                                    });

                                    it('should be the case that the rest go through when revert = 0 and there are two bad txs', async function () {
                                        const erc20Recipient = accounts[3];
                                        const erc721Recipient = accounts[4];
                                        const ethRecipient = utils.newKeyPair().address;
                                        const ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                        const erc20RecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(erc20Recipient));
                                        const erc721RecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(erc721Recipient));
                                        const walletOrigBalance = web3.utils.toBN(await web3.eth.getBalance(wallet.address));
                                        const transferAmount = web3.utils.toWei("10000", 'wei');

                                        // to (20), value (32), data length (32), data
                                        let dataArr = [];
                                        let revertBuff = Buffer.alloc(1);
                                        // no revert
                                        revertBuff.writeUInt8(0);
                                        dataArr.push(revertBuff);

                                        // transfer kitty to random addr
                                        // data argument
                                        dataArr.push(Buffer.from(erc721Token.address.replace('0x', ''), 'hex')); // address as string
                                        // value (32 bytes)
                                        dataArr.push(utils.numToBuffer(0));
                                        // create 721 data (attempt to transfer an nft you do not own)
                                        const erc721DataBuff = walletutils.erc721Transfer(firstTokenId + 10, wallet.address, erc721Recipient);
                                        dataArr.push(utils.numToBuffer(erc721DataBuff.length));
                                        dataArr.push(erc721DataBuff);

                                        // transfer ETH
                                        // 'to' is not padded (20 bytes)
                                        dataArr.push(Buffer.from(ethRecipient.replace('0x', ''), 'hex')); // address as string
                                        // value (32 bytes)
                                        dataArr.push(utils.numToBuffer(web3.utils.toWei("2", 'ether')));
                                        // data length (0)
                                        dataArr.push(utils.numToBuffer(0));
                                        // transfer ERC20
                                        // to
                                        dataArr.push(Buffer.from(erc20Token.address.replace('0x', ''), 'hex')); // address as string
                                        // value (32 bytes)
                                        dataArr.push(utils.numToBuffer(0));
                                        // amount
                                        const erc20Buff = walletutils.erc20Transfer(amount / 2, erc20Recipient);
                                        // push data length 
                                        dataArr.push(utils.numToBuffer(erc20Buff.length))
                                        // push data
                                        dataArr.push(erc20Buff);

                                        const data = Buffer.concat(dataArr);

                                        // get hash
                                        const operationHash = utils.getSha3ForConfirmationTx(
                                            wallet.address,
                                            nonce,
                                            adminPublicKey,
                                            data
                                        );

                                        //console.log("operationHash: 0x" + operationHash.toString('hex'));

                                        const sig1 = ethUtils.ecsign(operationHash, adminPrivateKey, walletutils.CHAIN_ID);
                                        const r = '0x' + sig1.r.toString('hex');
                                        const s = '0x' + sig1.s.toString('hex');
                                        const v = '0x' + Buffer.from([sig1.v]).toString('hex');

                                        // call invoke1CosignerSends
                                        const result = await wallet.invoke1CosignerSends(
                                            v, r, s,
                                            nonce,
                                            adminPublicKey,
                                            '0x' + data.toString('hex'),
                                            { from: cosignerPublicKey }
                                        );

                                        result.logs.length.should.eql(1);
                                        result.logs[0].args["numOperations"].should.eql(web3.utils.toBN(3));
                                        result.logs[0].args["hash"].should.eql('0x' + operationHash.toString('hex'));
                                        // should be fail, fail success, so 011
                                        result.logs[0].args["result"].should.eql(web3.utils.toBN(3));

                                        // check eth balances
                                        const ethRecipientNewBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                        ethRecipientNewBalance.should.eql(ethRecipientOrigBalance);
                                        const erc20RecipientNewBalance = web3.utils.toBN(await web3.eth.getBalance(erc20Recipient));
                                        erc20RecipientNewBalance.should.eql(erc20RecipientOrigBalance);
                                        const erc721RecipientNewBalance = web3.utils.toBN(await web3.eth.getBalance(erc721Recipient));
                                        erc721RecipientNewBalance.should.eql(erc721RecipientOrigBalance);
                                        const walletNewBalance = web3.utils.toBN(await web3.eth.getBalance(wallet.address));
                                        walletNewBalance.should.eql(walletOrigBalance);

                                        // check the ERC20 token balances
                                        const senderBalance = await erc20Token.balanceOf(erc20Owner);
                                        assert.equal(senderBalance, totalSupply - amount);

                                        const contractBalance = await erc20Token.balanceOf(wallet.address);
                                        assert.equal(contractBalance, amount / 2);

                                        const recipientBalance = await erc20Token.balanceOf(erc20Recipient);
                                        assert.equal(recipientBalance, amount / 2);

                                        // ERC721
                                        const newOwner = await erc721Token.ownerOf(firstTokenId);
                                        newOwner.should.be.equal(wallet.address);

                                        const newOwnerBalance = await erc721Token.balanceOf(erc721Recipient);
                                        newOwnerBalance.should.eql(web3.utils.toBN(0));

                                        const previousOwnerBalance = await erc721Token.balanceOf(wallet.address);
                                        previousOwnerBalance.should.eql(web3.utils.toBN(1));
                                    });

                                    it('should be the case that the rest don\'t go through when revert = 1', async function () {
                                        const erc20Recipient = accounts[3];
                                        const erc721Recipient = accounts[4];
                                        const ethRecipient = utils.newKeyPair().address;
                                        const ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                        const erc20RecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(erc20Recipient));
                                        const erc721RecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(erc721Recipient));
                                        const transferAmount = web3.utils.toWei("10000", 'wei');
                                        const walletOriginalBalance = web3.utils.toBN(await web3.eth.getBalance(wallet.address));

                                        // to (20), value (32), data length (32), data
                                        let dataArr = [];
                                        let revertBuff = Buffer.alloc(1);
                                        // no revert
                                        revertBuff.writeUInt8(1);
                                        dataArr.push(revertBuff);

                                        // transfer ETH
                                        // 'to' is not padded (20 bytes)
                                        dataArr.push(Buffer.from(ethRecipient.replace('0x', ''), 'hex')); // address as string
                                        // value (32 bytes)
                                        dataArr.push(utils.numToBuffer(transferAmount));
                                        // data length (0)
                                        dataArr.push(utils.numToBuffer(0));
                                        // transfer ERC20
                                        // to
                                        dataArr.push(Buffer.from(erc20Token.address.replace('0x', ''), 'hex')); // address as string
                                        // value (32 bytes)
                                        dataArr.push(utils.numToBuffer(0));
                                        // push data length (Transfer more than you have)
                                        const erc20Buff = walletutils.erc20Transfer(amount * 1000, erc20Recipient);
                                        dataArr.push(utils.numToBuffer(erc20Buff.length))
                                        // push data
                                        dataArr.push(erc20Buff);

                                        // transfer kitty to random addr
                                        // data argument
                                        dataArr.push(Buffer.from(erc721Token.address.replace('0x', ''), 'hex')); // address as string
                                        // value (32 bytes)
                                        dataArr.push(utils.numToBuffer(0));
                                        // create 721 data
                                        const erc721DataBuff = walletutils.erc721Transfer(firstTokenId, wallet.address, erc721Recipient);
                                        dataArr.push(utils.numToBuffer(erc721DataBuff.length));
                                        dataArr.push(erc721DataBuff);
                                        const data = Buffer.concat(dataArr);

                                        // get hash
                                        const operationHash = utils.getSha3ForConfirmationTx(
                                            wallet.address,
                                            nonce,
                                            adminPublicKey,
                                            data
                                        );

                                        //console.log("operationHash: 0x" + operationHash.toString('hex'));

                                        const sig1 = ethUtils.ecsign(operationHash, adminPrivateKey, walletutils.CHAIN_ID);
                                        const r = '0x' + sig1.r.toString('hex');
                                        const s = '0x' + sig1.s.toString('hex');
                                        const v = '0x' + Buffer.from([sig1.v]).toString('hex');

                                        // call invoke1CosignerSends
                                        await utils.expectThrow(
                                            wallet.invoke1CosignerSends(
                                                v, r, s,
                                                nonce,
                                                adminPublicKey,
                                                '0x' + data.toString('hex'),
                                                { from: cosignerPublicKey }
                                            )
                                        );

                                        // TODO: verify that nothing has changed
                                        const ethRecipientNewBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                        ethRecipientNewBalance.should.eql(ethRecipientOrigBalance);
                                        const walletNewBalance = web3.utils.toBN(await web3.eth.getBalance(wallet.address));
                                        walletNewBalance.should.eql(walletOriginalBalance);

                                        // check the ERC20 token balances
                                        const senderBalance = await erc20Token.balanceOf(erc20Owner);
                                        assert.equal(senderBalance, totalSupply - amount);

                                        const contractBalance = await erc20Token.balanceOf(wallet.address);
                                        assert.equal(contractBalance, amount);

                                        const recipientBalance = await erc20Token.balanceOf(erc20Recipient);
                                        assert.equal(recipientBalance, 0);

                                        // check eth balances to be sure no weirdness happened
                                        // recipientAmount
                                        let recipAmt = web3.utils.toBN(await web3.eth.getBalance(erc20Recipient));
                                        // receiver amount
                                        recipAmt.should.eql(erc20RecipientOrigBalance);

                                        // ERC721
                                        const newOwner = await erc721Token.ownerOf(firstTokenId);
                                        newOwner.should.be.equal(wallet.address);

                                        const newOwnerBalance = await erc721Token.balanceOf(erc721Recipient);
                                        newOwnerBalance.should.eql(web3.utils.toBN(0));

                                        const previousOwnerBalance = await erc721Token.balanceOf(wallet.address);
                                        previousOwnerBalance.should.eql(web3.utils.toBN(1));

                                        // check eth balances to be sure no weirdness happened
                                        // recipientAmount
                                        recipAmt = web3.utils.toBN(await web3.eth.getBalance(erc721Recipient));
                                        // receiver amount
                                        recipAmt.should.eql(erc721RecipientOrigBalance);
                                    });
                                });

                                describe('when the contract owner transfers Ξ, erc20 and erc721 tokens via multisend second sig cosigner with revert = 1', function () {

                                    const erc20Recipient = accounts[3];
                                    const erc721Recipient = accounts[4];
                                    const ethRecipient = utils.newKeyPair().address;
                                    let ethRecipientOrigBalance;
                                    const transferAmount = web3.utils.toWei("10000", 'wei');

                                    beforeEach(async function () {

                                        ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));

                                        // to (20), value (32), data length (32), data
                                        let dataArr = [];
                                        let revertBuff = Buffer.alloc(1);
                                        // revert flag
                                        revertBuff.writeUInt8(1);
                                        dataArr.push(revertBuff);
                                        // transfer ETH
                                        // 'to' is not padded (20 bytes)
                                        dataArr.push(Buffer.from(ethRecipient.replace('0x', ''), 'hex')); // address as string
                                        // value (32 bytes)
                                        dataArr.push(utils.numToBuffer(transferAmount));
                                        //console.log("transferAmount: " + utils.numToBuffer(transferAmount).toString('hex'));
                                        // data length (0)
                                        dataArr.push(utils.numToBuffer(0));
                                        // transfer ERC20
                                        // to
                                        dataArr.push(Buffer.from(erc20Token.address.replace('0x', ''), 'hex')); // address as string
                                        // value (32 bytes)
                                        dataArr.push(utils.numToBuffer(0));
                                        // push data length
                                        const erc20Buff = walletutils.erc20Transfer(amount / 2, erc20Recipient);
                                        dataArr.push(utils.numToBuffer(erc20Buff.length))
                                        // push data
                                        dataArr.push(erc20Buff);

                                        // transfer kitty to random addr
                                        // data argument

                                        dataArr.push(Buffer.from(erc721Token.address.replace('0x', ''), 'hex')); // address as string
                                        // value (32 bytes)
                                        dataArr.push(utils.numToBuffer(0));
                                        // erc721 data
                                        const erc721DataBuff = walletutils.erc721Transfer(firstTokenId, wallet.address, erc721Recipient);
                                        dataArr.push(utils.numToBuffer(erc721DataBuff.length));
                                        dataArr.push(erc721DataBuff);
                                        // concat all buffers
                                        //console.log('data: 0x' + Buffer.concat(dataArr).toString('hex'));

                                        const signer = accounts[2];

                                        const gas = await walletutils.transact2(
                                            Buffer.concat(dataArr),
                                            wallet,
                                            nonce,
                                            {
                                                address1: adminPublicKey,
                                                private1: adminPrivateKey,
                                                address2: cosignerPublicKey,
                                                private2: cosignerPrivateKey
                                            },
                                            signer
                                        );

                                        logGasPrice(wtype, INVOKE2, TRANSFER_MULTI, gas);

                                        // TODO: analyze logs
                                        // result.logs[0].args["numOperations"].should.eql(web3.utils.toBN(3));
                                        // result.logs[0].args["hash"].should.eql('0x' + operationHash.toString('hex'));
                                        // result.logs[0].args["result"].should.eql(web3.utils.toBN(0));
                                    });

                                    // Multisend
                                    it('should report correct erc20 and erc721 token and Ξ balances', async function () {

                                        // check ETH balances
                                        checkBalances(
                                            transferAmount,
                                            fundAmount,
                                            wallet.address,
                                            ethRecipient,
                                            ethRecipientOrigBalance
                                        );

                                        // check the ERC20 token balances
                                        const senderBalance = await erc20Token.balanceOf(erc20Owner);
                                        assert.equal(senderBalance, totalSupply - amount);

                                        const contractBalance = await erc20Token.balanceOf(wallet.address);
                                        //console.log(contractBalance);
                                        assert.equal(contractBalance, amount / 2);

                                        const recipientBalance = await erc20Token.balanceOf(erc20Recipient);
                                        assert.equal(recipientBalance, amount / 2);

                                        // check eth balances to be sure no weirdness happened
                                        let erc20RecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(erc20Recipient));

                                        let tBig = web3.utils.toBN(transferAmount);
                                        let remaining = (web3.utils.toBN(fundAmount)).sub(tBig);
                                        // left in wallet
                                        web3.utils.toBN(await web3.eth.getBalance(wallet.address)).eq(remaining).should.eql(true);
                                        // recipeintAmount
                                        let recipAmt = web3.utils.toBN(await web3.eth.getBalance(erc20Recipient));
                                        // reciever amount
                                        recipAmt.eq(erc20RecipientOrigBalance).should.eql(true);

                                        // ERC721
                                        const newOwner = await erc721Token.ownerOf(firstTokenId);
                                        newOwner.should.be.equal(erc721Recipient);

                                        const newOwnerBalance = await erc721Token.balanceOf(erc721Recipient);
                                        newOwnerBalance.eq(web3.utils.toBN("1")).should.eql(true);

                                        const previousOwnerBalance = await erc721Token.balanceOf(wallet.address);
                                        previousOwnerBalance.eq(web3.utils.toBN("0")).should.eql(true);

                                        // check eth balances to be sure no weirdness happened
                                        let erc721RecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(erc721Recipient));

                                        tBig = web3.utils.toBN(transferAmount);
                                        remaining = (web3.utils.toBN(fundAmount)).sub(tBig);
                                        // left in wallet
                                        web3.utils.toBN(await web3.eth.getBalance(wallet.address)).eq(remaining).should.eql(true);
                                        // recipeintAmount
                                        recipAmt = web3.utils.toBN(await web3.eth.getBalance(erc721Recipient));
                                        // reciever amount
                                        recipAmt.eq(erc721RecipientOrigBalance).should.eql(true);

                                    });
                                });

                                describe('when the contract owner transfers Ξ, erc20 and erc721 tokens via multisend second sig cosigner with revert = 0', function () {

                                    const erc20Recipient = accounts[3];
                                    const erc721Recipient = accounts[4];
                                    const ethRecipient = utils.newKeyPair().address;
                                    let ethRecipientOrigBalance;
                                    const transferAmount = web3.utils.toWei("10000", 'wei');

                                    beforeEach(async function () {

                                        ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));

                                        // to (20), value (32), data length (32), data
                                        let dataArr = [];
                                        let revertBuff = Buffer.alloc(1);
                                        // revert flag
                                        revertBuff.writeUInt8(0);
                                        dataArr.push(revertBuff);

                                        // transfer ERC20
                                        // to
                                        dataArr.push(Buffer.from(erc20Token.address.replace('0x', ''), 'hex')); // address as string
                                        // value (32 bytes)
                                        dataArr.push(utils.numToBuffer(0));
                                        // push data length
                                        const erc20Buff = walletutils.erc20Transfer(amount / 2, erc20Recipient);
                                        dataArr.push(utils.numToBuffer(erc20Buff.length))
                                        // push data
                                        dataArr.push(erc20Buff);

                                        // transfer kitty to random addr
                                        // data argument

                                        dataArr.push(Buffer.from(erc721Token.address.replace('0x', ''), 'hex')); // address as string
                                        // value (32 bytes)
                                        dataArr.push(utils.numToBuffer(0));
                                        // erc721 data
                                        const erc721DataBuff = walletutils.erc721Transfer(firstTokenId, wallet.address, erc721Recipient);
                                        dataArr.push(utils.numToBuffer(erc721DataBuff.length));
                                        dataArr.push(erc721DataBuff);
                                        // concat all buffers
                                        //console.log('data: 0x' + Buffer.concat(dataArr).toString('hex'));

                                        // transfer ETH
                                        // 'to' is not padded (20 bytes)
                                        dataArr.push(Buffer.from(ethRecipient.replace('0x', ''), 'hex')); // address as string
                                        // value (32 bytes)
                                        dataArr.push(utils.numToBuffer(transferAmount));
                                        //console.log("transferAmount: " + utils.numToBuffer(transferAmount).toString('hex'));
                                        // data length (0)
                                        dataArr.push(utils.numToBuffer(0));

                                        const signer = accounts[2];

                                        const gas = await walletutils.transact2(
                                            Buffer.concat(dataArr),
                                            wallet,
                                            nonce,
                                            {
                                                address1: adminPublicKey,
                                                private1: adminPrivateKey,
                                                address2: cosignerPublicKey,
                                                private2: cosignerPrivateKey
                                            },
                                            signer
                                        );

                                        logGasPrice(wtype, INVOKE2, TRANSFER_MULTI, gas);

                                        // TODO: analyze logs
                                        // result.logs[0].args["numOperations"].should.eql(web3.utils.toBN(3));
                                        // result.logs[0].args["hash"].should.eql('0x' + operationHash.toString('hex'));
                                        // result.logs[0].args["result"].should.eql(web3.utils.toBN(0));
                                    });

                                    // Multisend
                                    it('should report correct erc20 and erc721 token and Ξ balances', async function () {

                                        // check ETH balances
                                        checkBalances(
                                            transferAmount,
                                            fundAmount,
                                            wallet.address,
                                            ethRecipient,
                                            ethRecipientOrigBalance
                                        );

                                        // check the ERC20 token balances
                                        const senderBalance = await erc20Token.balanceOf(erc20Owner);
                                        assert.equal(senderBalance, totalSupply - amount);

                                        const contractBalance = await erc20Token.balanceOf(wallet.address);
                                        //console.log(contractBalance);
                                        assert.equal(contractBalance, amount / 2);

                                        const recipientBalance = await erc20Token.balanceOf(erc20Recipient);
                                        assert.equal(recipientBalance, amount / 2);

                                        // check eth balances to be sure no weirdness happened
                                        let erc20RecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(erc20Recipient));

                                        let tBig = web3.utils.toBN(transferAmount);
                                        let remaining = (web3.utils.toBN(fundAmount)).sub(tBig);
                                        // left in wallet
                                        web3.utils.toBN(await web3.eth.getBalance(wallet.address)).eq(remaining).should.eql(true);
                                        // recipeintAmount
                                        let recipAmt = web3.utils.toBN(await web3.eth.getBalance(erc20Recipient));
                                        // reciever amount
                                        recipAmt.eq(erc20RecipientOrigBalance).should.eql(true);

                                        // ERC721
                                        const newOwner = await erc721Token.ownerOf(firstTokenId);
                                        newOwner.should.be.equal(erc721Recipient);

                                        const newOwnerBalance = await erc721Token.balanceOf(erc721Recipient);
                                        newOwnerBalance.eq(web3.utils.toBN("1")).should.eql(true);

                                        const previousOwnerBalance = await erc721Token.balanceOf(wallet.address);
                                        previousOwnerBalance.eq(web3.utils.toBN("0")).should.eql(true);

                                        // check eth balances to be sure no weirdness happened
                                        let erc721RecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(erc721Recipient));

                                        tBig = web3.utils.toBN(transferAmount);
                                        remaining = (web3.utils.toBN(fundAmount)).sub(tBig);
                                        // left in wallet
                                        web3.utils.toBN(await web3.eth.getBalance(wallet.address)).eq(remaining).should.eql(true);
                                        // recipeintAmount
                                        recipAmt = web3.utils.toBN(await web3.eth.getBalance(erc721Recipient));
                                        // reciever amount
                                        recipAmt.eq(erc721RecipientOrigBalance).should.eql(true);

                                    });
                                });

                            });

                        });

                    });

                    describe('concerning malformed inputs', function () {

                        it('should revert if we provide data.length too long', async function () {

                            let dataArr = [];
                            let revertBuff = Buffer.alloc(1);
                            // don't revert for now
                            revertBuff.writeUInt8(0);
                            dataArr.push(revertBuff);

                            // 'to' is not padded (20 bytes)
                            dataArr.push(Buffer.from(utils.newKeyPair().address.replace('0x', ''), 'hex')); // address as string
                            // value (32 bytes)
                            dataArr.push(utils.numToBuffer(web3.utils.toWei("1", 'wei')));
                            // data length (0)
                            dataArr.push(utils.numToBuffer(22));

                            await utils.expectThrow(
                                walletutils.transact1(
                                    Buffer.concat(dataArr),
                                    wallet,
                                    nonce,
                                    { address1: adminPublicKey, private1: adminPrivateKey },
                                    cosignerPublicKey
                                )
                            );
                        });




                        // try to lie;
                        // case 1: don't provide length (or missing argument)
                        // remove a parameter? => 
                        // send to an "accepting" contract? (default function)
                        // lie about lengths of data
                        //   - say 20, but provide 30 -> will get next instr wrong
                        //   - say 20 but provide 10 -> will get next instr wrong (if last, should revert)
                    });
                });
            });
        });

        describe('without a cosigner', function () {

            beforeEach(async function () {
                cosignerPublicKey = adminPublicKey;
                cosignerPrivateKey = adminPrivateKey;

                fullCosignerKey = metaData.add(web3.utils.toBN(cosignerPublicKey));

                // create wallet
                wallet = await walletutils.createWallet(
                    wtype,
                    masterPublicKey,
                    adminPublicKey,
                    fullCosignerKey,
                    _walletFactory,
                    salt
                );
            });

            it('should be able to get the version', async function () {
                const version = await wallet.VERSION.call();
                version.should.eql("1.1.0");
            });

            it('should be at the expected address if using create2', async function () {
                if (wtype == walletutils.WALLET_CLONE_2) {
                    const _bytecode = "0x3d602d80600a3d3981f3363d3d373d3d3d363d73" +
                        _cloneAddress.replace("0x", "") + "5af43d82803e903d91602b57fd5bf3";
                    const newsalt = abi.soliditySHA3(
                        ['bytes32', 'address', 'uint256', 'address'],
                        [salt, adminPublicKey, fullCosignerKey, masterPublicKey]
                    );
                    let addr = utils.buildCreate2Address(_walletFactory.address, '0x' + newsalt.toString('hex'), _bytecode);
                    addr = web3.utils.toChecksumAddress(addr);
                    addr.should.eql(wallet.address);
                } else if (wtype == walletutils.WALLET_REGULAR_2) {
                    // get the bytecode from the contract
                    // const accountBytecode = wallet.constructor.bytecode;
                    // replicate what was sent to the network
                    const bytecode = `${fullBytecode}${web3.eth.abi.encodeParameter('address', adminPublicKey).slice(2)}${web3.eth.abi.encodeParameter('uint256', '0x' + fullCosignerKey.toString('hex')).slice(2)}${web3.eth.abi.encodeParameter('address', masterPublicKey).slice(2)}`
                    //console.log(bytecode);
                    let addr = utils.buildCreate2Address(_walletFactory.address, salt, bytecode);
                    addr = web3.utils.toChecksumAddress(addr);
                    addr.should.eql(wallet.address);
                }
            });

            describe('concerning extensibility', function () {
                const RANDOM_METHOD_ID = "12345678";
                const DO_SOMETHING_ID = utils.funcHash("doSomething()").toString("hex");
                const DO_SOMETHING_ELSE_ID = utils.funcHash("doSomethingElse(uint256)").toString("hex");
                const DO_SOMETHING_THAT_REVERTS_ID = utils.funcHash("doSomethingThatReverts()").toString("hex");
                const DO_SOMETHING_THAT_WRITES_TO_STORAGE_ID = utils.funcHash("doSomethingThatWritesToStorage()").toString("hex");
                const COMPOSITE_INTERFACE_ID = 'f8a4fb69';
                const DELEGATE_IGNORE = '0x1';
                
                let delegate, checker;

                beforeEach(async function () {
                    delegate = await Delegate.new();   
                    checker = await ERC165Checker.new();
                });

                it('should revert for unsupported interface', function () {
                    utils.expectThrow(
                        walletutils.callDynamic(wallet, RANDOM_METHOD_ID) 
                    );
                });
                
                it('should not be able to call setDelegate directly', async function () {
                    await utils.expectThrow(
                        wallet.setDelegate('0x'+utils.padBytes4(DO_SOMETHING_ID), delegate.address)
                    );
                });

                it('should be able to set a delegate', async function () {
                    const res = await wallet.invoke0(
                        '0x'+walletutils.txData(
                            1, // revert (stricter)
                            wallet.address,
                            web3.utils.toWei("0", 'wei'),
                            setDelegateData(DO_SOMETHING_ID, delegate.address)).toString('hex'),
                        { from: adminPublicKey }
                    );
                    res.logs[0].event.should.eql('DelegateUpdated');
                    res.logs[0].args['interfaceId'].should.eql('0x'+DO_SOMETHING_ID);
                    res.logs[0].args['delegate'].should.eql(delegate.address);
                });

                describe('with delegate set for SimpleInterface', function () {
                    beforeEach(async function () {
                        await walletutils.transact0(walletutils.txData(
                                1, // revert (stricter)
                                wallet.address,
                                web3.utils.toWei("0", 'wei'),
                                setDelegateData(DO_SOMETHING_ID, delegate.address)
                            ), 
                            wallet, 
                            adminPublicKey
                        );  
                    });

                    it('should show delegate in mapping', async function () {
                        const addr = await wallet.delegates("0x"+utils.padBytes4(DO_SOMETHING_ID));
                        addr.should.eql(delegate.address);
                    });

                    it('should pass calls to doSomething to the delegate', async function () {
                        const res = await walletutils.callDynamic(wallet, DO_SOMETHING_ID);
                        web3.utils.toBN(res).toNumber().should.eql(42);
                    });

                    it('should support interface for SimpleInterface', async function () {
                        const res = await checker.checkInterfaces(wallet.address, ['0x'+DO_SOMETHING_ID]);
                        res.should.eql(true);
                    });

                    it('should be able to remove delegate', async function () {
                        await walletutils.transact0(walletutils.txData(
                                1, // revert (stricter)
                                wallet.address,
                                web3.utils.toWei("0", 'wei'),
                                setDelegateData(DO_SOMETHING_ID, `0x${'0'.repeat(40)}`)
                            ), 
                            wallet, 
                            adminPublicKey
                        );
                    });

                    describe('with SimpleInterface delegate removed', async function () {
                        beforeEach(async function () {
                            await walletutils.transact0(walletutils.txData(
                                    1, // revert (stricter)
                                    wallet.address,
                                    web3.utils.toWei("0", 'wei'),
                                    setDelegateData(DO_SOMETHING_ID, `0x${'0'.repeat(40)}`)
                                ), 
                                wallet, 
                                adminPublicKey
                            );
                        });

                        it('should not show delegate in mapping', async function () {
                            const addr = await wallet.delegates("0x"+utils.padBytes4(DO_SOMETHING_ID));
                            addr.should.eql(`0x${'0'.repeat(40)}`);
                        });

                        it('should revert on calls to doSomething', async function () {
                            utils.expectThrow(
                                walletutils.callDynamic(wallet, DO_SOMETHING_ID) 
                            );
                        });
                    });
                });

                describe('with delegate set for CompositeInterface', function () {
                    beforeEach(async function () {
                        // set delegates for both functions
                        await walletutils.transact0(walletutils.txData(
                                1, // revert (stricter)
                                wallet.address,
                                web3.utils.toWei("0", 'wei'),
                                setDelegateData(DO_SOMETHING_ID, delegate.address)
                            ), 
                            wallet, 
                            adminPublicKey
                        );

                        await walletutils.transact0(walletutils.txData(
                                1, // revert (stricter)
                                wallet.address,
                                web3.utils.toWei("0", 'wei'),
                                setDelegateData(DO_SOMETHING_ELSE_ID, delegate.address)
                            ), 
                            wallet, 
                            adminPublicKey
                        );
                    });

                    it('should pass calls to doSomething and doSomethingElse', async function () {
                        let res = await walletutils.callDynamic(wallet, DO_SOMETHING_ID);
                        let resBN = web3.utils.toBN(res)
                        resBN.toNumber().should.eql(42);

                        res = await walletutils.callDynamic(
                            wallet, 
                            DO_SOMETHING_ELSE_ID, 
                            utils.numToBuffer(2).toString('hex')
                        );
                        web3.utils.toBN(res).toNumber().should.eql(2);
                    });

                    it('should support interface for both functions of CompositeInterface', async function () {
                        const res = await checker.checkInterfaces(wallet.address, ['0x'+DO_SOMETHING_ID, '0x'+DO_SOMETHING_ELSE_ID]);
                        res.should.eql(true);
                    });

                    it('should NOT support interface for CompositeInterface', async function () {
                        const res = await checker.checkInterfaces(wallet.address, ['0x'+COMPOSITE_INTERFACE_ID]);
                        res.should.eql(false);
                    });

                    describe('with composite interface ID support specified', function () {
                        beforeEach(async function () {
                            await walletutils.transact0(walletutils.txData(
                                    1, // revert (stricter)
                                    wallet.address,
                                    web3.utils.toWei("0", 'wei'),
                                    setDelegateData(COMPOSITE_INTERFACE_ID, DELEGATE_IGNORE)
                                ), 
                                wallet, 
                                adminPublicKey
                            );   
                        });

                        it('should support interface for CompositeInterface', async function () {
                            const res = await checker.checkInterfaces(wallet.address, ['0x'+COMPOSITE_INTERFACE_ID]);
                            res.should.eql(true);
                        });

                        it('should revert when attempting to call function corresponding to CompositeInterface ID', async function () {
                            utils.expectThrow(
                               walletutils.callDynamic(wallet, COMPOSITE_INTERFACE_ID) 
                            );
                        });
                    });

                    describe('with revert and write functions added', function () {
                        beforeEach(async function () {
                            await walletutils.transact0(walletutils.txData(
                                    1, // revert (stricter)
                                    wallet.address,
                                    web3.utils.toWei("0", 'wei'),
                                    setDelegateData(DO_SOMETHING_THAT_REVERTS_ID, delegate.address)
                                ), 
                                wallet, 
                                adminPublicKey
                            );

                            await walletutils.transact0(walletutils.txData(
                                    1, // revert (stricter)
                                    wallet.address,
                                    web3.utils.toWei("0", 'wei'),
                                    setDelegateData(DO_SOMETHING_THAT_WRITES_TO_STORAGE_ID, delegate.address)
                                ), 
                                wallet, 
                                adminPublicKey
                            );
                        });

                        it('should revert if the delegate reverts', async function () {
                            await utils.expectThrow(
                                walletutils.callDynamic(
                                    wallet, 
                                    DO_SOMETHING_THAT_REVERTS_ID
                                )
                            );
                        });

                        it('should revert if it attempts to write to storage', async function () {
                            await utils.expectThrow(
                                walletutils.callDynamic(
                                    wallet, 
                                    DO_SOMETHING_THAT_WRITES_TO_STORAGE_ID 
                                )
                            );
                        });
                    });
                });
            }); 

            describe('concerning ERC1271 compatibility', function () {
                const data = "hello worlds";
                const ERC1271_VS = "0x1626ba7e";

                it('should be able to validate a signature', async function () {
                    // prepare a signature from the signer and the cosigner
                    const dataHash = abi.soliditySHA3(['string'], [data]);
                    const hashToSign = utils.getSha3ForERC1271(
                        wallet.address,
                        dataHash
                    );

                    const sig1 = ethUtils.ecsign(hashToSign, adminPrivateKey, 0);
                    const combined = '0x' + sig1.r.toString('hex') + sig1.s.toString('hex') + Buffer.from([sig1.v]).toString('hex');
                    // call contract
                    const result = await wallet.isValidSignature('0x' + dataHash.toString('hex'), combined);
                    // check result
                    result.should.eql(ERC1271_VS);
                });

                it('should be able to validate a signature with two signatures', async function () {
                    // prepare a signature from the signer and the cosigner
                    const dataHash = abi.soliditySHA3(['string'], [data]);
                    const hashToSign = utils.getSha3ForERC1271(
                        wallet.address,
                        dataHash
                    );

                    const sig1 = ethUtils.ecsign(hashToSign, adminPrivateKey, 0);
                    const sig2 = ethUtils.ecsign(hashToSign, adminPrivateKey, 0);
                    const combined = '0x' + sig1.r.toString('hex') + sig1.s.toString('hex') + Buffer.from([sig1.v]).toString('hex') +
                        sig2.r.toString('hex') + sig2.s.toString('hex') + Buffer.from([sig2.v]).toString('hex');
                    // call contract
                    const result = await wallet.isValidSignature('0x' + dataHash.toString('hex'), combined);
                    // check result
                    result.should.eql(ERC1271_VS);
                });

                it('should return 0 if provided an invalid signature', async function () {
                    const dataHash = abi.soliditySHA3(['string'], [data]);
                    const hashToSign = utils.getSha3ForERC1271(
                        wallet.address,
                        dataHash
                    );

                    const sig1 = ethUtils.ecsign(hashToSign, adminPrivateKey, 0);
                    const combined = '0x' + sig1.r.toString('hex') + sig1.s.toString('hex') + Buffer.from([sig1.v]).toString('hex');
                    // mess with the signature
                    const result = await wallet.isValidSignature('0x' + dataHash.toString('hex'), incrementCharAt(combined, 10));
                    result.should.eql("0x00000000");
                });

                it('should return 0 if provided an invalid signature length', async function () {
                    const dataHash = abi.soliditySHA3(['string'], [data]);
                    const hashToSign = utils.getSha3ForERC1271(
                        wallet.address,
                        dataHash
                    );

                    const sig1 = ethUtils.ecsign(hashToSign, adminPrivateKey, 0);
                    const combined = '0x' + sig1.r.toString('hex') + sig1.s.toString('hex') + Buffer.from([sig1.v]).toString('hex');

                    const result = await wallet.isValidSignature('0x' + dataHash.toString('hex'), combined.substring(0, combined.length - 10));
                    result.should.eql("0x00000000");
                });


                it('should return 0 if given signature from a key that is not an authorized key', async function () {
                    const dataHash = abi.soliditySHA3(['string'], [data]);
                    const hashToSign = utils.getSha3ForERC1271(
                        wallet.address,
                        dataHash
                    );

                    // use cosigner as authorized key
                    const sig1 = ethUtils.ecsign(hashToSign, masterPrivateKey, 0);
                    const combined = '0x' + sig1.r.toString('hex') + sig1.s.toString('hex') + Buffer.from([sig1.v]).toString('hex');
                    const result = await wallet.isValidSignature('0x' + dataHash.toString('hex'), combined);
                    result.should.eql("0x00000000");
                });
            });

            describe('when wallet is funded', function () {
                beforeEach(async function () {
                    // fund the wallet
                    await walletutils.fundAddress(funder, wallet.address, fundAmount);
                });

                describe('when performing transactions', function () {

                    describe('when sending eth via admin key', function () {

                        let ethRecipient;
                        const transferAmount = web3.utils.toWei("10000", 'wei');

                        describe('to account address', function () {

                            beforeEach(function () {
                                ethRecipient = accounts[3];
                            });

                            it('should revert if wrong nonce is used', async function () {
                                const ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                await utils.expectThrow(
                                    walletutils.transact1Twice(
                                        walletutils.txData(0, ethRecipient, transferAmount, Buffer.from('')),
                                        wallet,
                                        255,
                                        { address1: adminPublicKey, private1: adminPrivateKey },
                                        cosignerPublicKey
                                    ));

                                const nonce = await walletutils.getNonce(wallet, adminPublicKey);

                                await utils.expectThrow(
                                    walletutils.transact1Twice(
                                        walletutils.txData(0, ethRecipient, transferAmount, Buffer.from('')),
                                        wallet,
                                        nonce + 1,
                                        { address1: adminPublicKey, private1: adminPrivateKey },
                                        cosignerPublicKey
                                    ));

                                const newBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                newBalance.should.eql(ethRecipientOrigBalance);
                            });

                            describe('after sending eth', function () {
                                let ethRecipientOrigBalance;

                                beforeEach(async function () {
                                    ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                                });

                                describe('with revert flag', function () {
                                    let revert;

                                    describe('set to 0', async function () {
                                        beforeEach(async function () {
                                            revert = 0;

                                            const gas = await walletutils.transact0Twice(
                                                walletutils.txData(
                                                    revert,
                                                    ethRecipient,
                                                    transferAmount,
                                                    Buffer.from('')
                                                ),
                                                wallet,
                                                adminPublicKey
                                            );

                                            logGasPrice(wtype, INVOKE0, TRANSFER_ETH, gas);
                                        });

                                        it('should report proper balances', async function () {
                                            checkBalances(
                                                transferAmount * 2,
                                                fundAmount,
                                                wallet.address,
                                                ethRecipient,
                                                ethRecipientOrigBalance
                                            );
                                        });

                                    });

                                    describe('set to 1', async function () {
                                        beforeEach(async function () {
                                            revert = 1;

                                            const gas = await walletutils.transact0Twice(
                                                walletutils.txData(
                                                    revert,
                                                    ethRecipient,
                                                    transferAmount,
                                                    Buffer.from('')
                                                ),
                                                wallet,
                                                adminPublicKey
                                            );

                                            logGasPrice(wtype, INVOKE0, TRANSFER_ETH, gas);
                                        });

                                        it('should report proper balances', async function () {
                                            checkBalances(
                                                transferAmount * 2,
                                                fundAmount,
                                                wallet.address,
                                                ethRecipient,
                                                ethRecipientOrigBalance
                                            );
                                        });

                                    });

                                });
                            });
                        })
                    });

                    describe('with regards to erc20 tokens', function () {
                        // TODO
                        const erc20Owner = accounts[1];
                        const anotherAccount = accounts[2];
                        const totalSupply = 100
                        let token;

                        describe('when the erc20 token contract is created', function () {

                            beforeEach(async function () {
                                token = await StandardTokenMock.new(erc20Owner, totalSupply);
                            });

                            // basic tests to verify the contracts working
                            describe('when asked for the total token supply', function () {

                                it('returns the total amount of tokens', async function () {
                                    const total = await token.totalSupply();
                                    assert.equal(totalSupply, total);
                                });
                            });

                            describe('when asked for the balanceOf', function () {

                                describe('when the requested account has no tokens', function () {
                                    it('returns zero', async function () {
                                        const balance = await token.balanceOf(anotherAccount);
                                        assert.equal(balance, 0);
                                    });
                                });

                                describe('when the requested account has some tokens', function () {
                                    it('returns the total amount of tokens', async function () {
                                        const balance = await token.balanceOf(erc20Owner);
                                        assert.equal(balance, 100);
                                    });
                                });
                            });

                            // transfer some to contract owner
                            describe('when the contract owner owns erc20 tokens', function () {
                                const amount = totalSupply / 2; //50

                                beforeEach(async function () {
                                    await token.transfer(wallet.address, amount, { from: erc20Owner });

                                    const senderBalance = await token.balanceOf(erc20Owner);
                                    assert.equal(senderBalance, totalSupply - amount);

                                    const recipientBalance = await token.balanceOf(wallet.address);
                                    assert.equal(recipientBalance, amount);
                                });

                                describe('when the requested account has some tokens', function () {
                                    it('returns the total amount of tokens', async function () {
                                        const balance = await token.balanceOf(wallet.address);
                                        assert.equal(balance, amount);
                                    });
                                });

                                describe('when the contract owner transfers erc20 tokens with revert = 0', function () {

                                    const erc20Recipient = accounts[3];

                                    beforeEach(async function () {

                                        const gas = await walletutils.transact0Twice(
                                            walletutils.txData(
                                                0,
                                                token.address,
                                                web3.utils.toWei("0", 'kwei'),
                                                walletutils.erc20Transfer(amount / 2, erc20Recipient)
                                            ),
                                            wallet,
                                            adminPublicKey
                                        );

                                        logGasPrice(wtype, INVOKE0, TRANSFER_ERC20, gas);
                                    });

                                    it('should report correct erc20 token and Ξ balances', async function () {

                                        // check the token balances
                                        const senderBalance = await token.balanceOf(erc20Owner);
                                        assert.equal(senderBalance, totalSupply - amount);

                                        const contractBalance = await token.balanceOf(wallet.address);
                                        //console.log(contractBalance.toString(10)); // 0x32
                                        assert.equal(contractBalance, 0);

                                        const recipientBalance = await token.balanceOf(erc20Recipient);
                                        //console.log(recipientBalance.toString(10)); // 0x32
                                        assert.equal(recipientBalance, amount);

                                        // check eth balances to be sure no weirdness happened
                                        let erc20RecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(erc20Recipient));

                                        checkBalances(
                                            0,
                                            fundAmount,
                                            wallet.address,
                                            erc20Recipient,
                                            erc20RecipientOrigBalance
                                        );

                                        //console.table(gasPrices);
                                    });
                                });

                                describe('when the contract owner transfers erc20 tokens with revert = 1', function () {

                                    const erc20Recipient = accounts[3];

                                    beforeEach(async function () {

                                        const gas = await walletutils.transact0Twice(
                                            walletutils.txData(
                                                1,
                                                token.address,
                                                web3.utils.toWei("0", 'kwei'),
                                                walletutils.erc20Transfer(amount / 2, erc20Recipient)
                                            ),
                                            wallet,
                                            adminPublicKey
                                        );

                                        logGasPrice(wtype, INVOKE0, TRANSFER_ERC20, gas);
                                    });

                                    it('should report correct erc20 token and Ξ balances', async function () {

                                        // check the token balances
                                        const senderBalance = await token.balanceOf(erc20Owner);
                                        assert.equal(senderBalance, totalSupply - amount);

                                        const contractBalance = await token.balanceOf(wallet.address);
                                        //console.log(contractBalance.toString(10)); // 0x32
                                        assert.equal(contractBalance, 0);

                                        const recipientBalance = await token.balanceOf(erc20Recipient);
                                        //console.log(recipientBalance.toString(10)); // 0x32
                                        assert.equal(recipientBalance, amount);

                                        // check eth balances to be sure no weirdness happened
                                        let erc20RecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(erc20Recipient));

                                        checkBalances(
                                            0,
                                            fundAmount,
                                            wallet.address,
                                            erc20Recipient,
                                            erc20RecipientOrigBalance
                                        );

                                        //console.table(gasPrices);
                                    });
                                });
                            });
                        });

                    });

                    describe('with regards to erc721', function () {
                        const name = 'Non Fungible Token';
                        const symbol = 'NFT';
                        const firstTokenId = 100;
                        const secondTokenId = 200;
                        const creator = accounts[0];
                        let token;

                        beforeEach(async function () {
                            token = await ERC721TokenMock.new(name, symbol, { from: creator });
                            await token.mint(creator, firstTokenId, { from: creator });
                            await token.mint(creator, secondTokenId, { from: creator });
                        });


                        describe('totalSupply', function () {
                            it('returns total token supply', async function () {
                                const totalSupply = await token.totalSupply();
                                totalSupply.should.eql(web3.utils.toBN(2));
                            });
                        });

                        describe('balanceOf', function () {
                            describe('when the given address owns some tokens', function () {
                                it('returns the amount of tokens owned by the given address', async function () {
                                    const balance = await token.balanceOf(creator);
                                    balance.should.eql(web3.utils.toBN(2));
                                });
                            });

                            describe('when the given address does not own any tokens', function () {
                                it('returns 0', async function () {
                                    let balance = await token.balanceOf(accounts[1]);
                                    balance.should.eql(web3.utils.toBN(0));

                                    balance = await token.balanceOf(wallet.address);
                                    balance.should.eql(web3.utils.toBN(0));
                                });
                            });
                        });

                        describe('when the contract owner owns an erc721 token', function () {

                            beforeEach(async function () {
                                // send to contract owner
                                await token.transferFrom(creator, wallet.address, firstTokenId, { from: creator });
                                await token.transferFrom(creator, wallet.address, secondTokenId, { from: creator });
                            });

                            it('should say we own the token', async function () {

                                let newOwner = await token.ownerOf(firstTokenId);
                                newOwner.should.be.equal(wallet.address);

                                newOwner = await token.ownerOf(secondTokenId);
                                newOwner.should.be.equal(wallet.address);

                                const newOwnerBalance = await token.balanceOf(wallet.address);
                                newOwnerBalance.should.eql(web3.utils.toBN(2));

                                const previousOwnerBalance = await token.balanceOf(creator);
                                previousOwnerBalance.should.eql(web3.utils.toBN(0));
                            });

                            describe('when wallet transfers the token using transferFrom() with revert = 0', function () {

                                const recipient = utils.newKeyPair().address;

                                beforeEach(async function () {

                                    await walletutils.transact0(
                                        walletutils.txData(0, token.address, web3.utils.toWei("0", 'kwei'),
                                            walletutils.erc721Transfer(firstTokenId, wallet.address, recipient)),
                                        wallet,
                                        adminPublicKey
                                    );

                                    const gas = await walletutils.transact0(
                                        walletutils.txData(0, token.address, web3.utils.toWei("0", 'kwei'),
                                            walletutils.erc721Transfer(secondTokenId, wallet.address, recipient)),
                                        wallet,
                                        adminPublicKey
                                    );

                                    logGasPrice(wtype, INVOKE0, TRANSFER_ERC721, gas);
                                });

                                it('should say the new owner owns the token', async function () {

                                    let newOwner = await token.ownerOf(firstTokenId);
                                    newOwner.should.be.equal(recipient);

                                    newOwner = await token.ownerOf(secondTokenId);
                                    newOwner.should.be.equal(recipient);

                                    const newOwnerBalance = await token.balanceOf(recipient);
                                    //newOwnerBalance.should.be.bignumber.equal(1);
                                    newOwnerBalance.should.eql(web3.utils.toBN(2));

                                    const previousOwnerBalance = await token.balanceOf(wallet.address);
                                    //previousOwnerBalance.should.be.bignumber.equal(0);
                                    previousOwnerBalance.should.eql(web3.utils.toBN(0));

                                    // check eth balances to be sure no weirdness happened
                                    let erc721RecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(recipient));

                                    checkBalances(
                                        0,
                                        fundAmount,
                                        wallet.address,
                                        recipient,
                                        erc721RecipientOrigBalance
                                    );
                                });
                            });

                            describe('when wallet transfers the token using transferFrom() with revert = 0', function () {

                                const recipient = utils.newKeyPair().address;

                                beforeEach(async function () {

                                    await walletutils.transact0(
                                        walletutils.txData(1, token.address, web3.utils.toWei("0", 'kwei'),
                                            walletutils.erc721Transfer(firstTokenId, wallet.address, recipient)),
                                        wallet,
                                        adminPublicKey
                                    );

                                    const gas = await walletutils.transact0(
                                        walletutils.txData(1, token.address, web3.utils.toWei("0", 'kwei'),
                                            walletutils.erc721Transfer(secondTokenId, wallet.address, recipient)),
                                        wallet,
                                        adminPublicKey
                                    );

                                    logGasPrice(wtype, INVOKE0, TRANSFER_ERC721, gas);
                                });

                                it('should say the new owner owns the token', async function () {

                                    let newOwner = await token.ownerOf(firstTokenId);
                                    newOwner.should.be.equal(recipient);

                                    newOwner = await token.ownerOf(secondTokenId);
                                    newOwner.should.be.equal(recipient);

                                    const newOwnerBalance = await token.balanceOf(recipient);
                                    //newOwnerBalance.should.be.bignumber.equal(1);
                                    newOwnerBalance.should.eql(web3.utils.toBN(2));

                                    const previousOwnerBalance = await token.balanceOf(wallet.address);
                                    //previousOwnerBalance.should.be.bignumber.equal(0);
                                    previousOwnerBalance.should.eql(web3.utils.toBN(0));

                                    // check eth balances to be sure no weirdness happened
                                    let erc721RecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(recipient));

                                    checkBalances(
                                        0,
                                        fundAmount,
                                        wallet.address,
                                        recipient,
                                        erc721RecipientOrigBalance
                                    );
                                });
                            });
                        });
                    });

                    describe('with regards to multisend', function () {
                        // ETH

                        // ERC20 tokens
                        const erc20Owner = accounts[1];
                        const anotherAccount = accounts[2];
                        const totalSupply = 100
                        let erc20Token;

                        // ERC721 tokens
                        const name = 'Non Fungible Token 2';
                        const symbol = 'NFT 2';
                        const firstTokenId = 100;
                        const secondTokenId = 200;
                        const creator = accounts[0];
                        let erc721Token;

                        describe('when the contracts have been created', function () {
                            beforeEach(async function () {
                                // erc 20
                                erc20Token = await StandardTokenMock.new(erc20Owner, totalSupply);

                                // erc 721
                                erc721Token = await ERC721TokenMock.new(name, symbol, { from: creator });
                                await erc721Token.mint(creator, firstTokenId, { from: creator });
                                await erc721Token.mint(creator, secondTokenId, { from: creator });
                            });

                            // basic tests to verify the contracts working
                            describe('erc20 tokens', function () {

                                describe('when asked for the total erc20 token supply', function () {

                                    it('returns the total amount of tokens', async function () {
                                        const total = await erc20Token.totalSupply();
                                        assert.equal(totalSupply, total);
                                    });
                                });

                                describe('when asked for the balanceOf', function () {

                                    describe('when the requested account has no tokens', function () {
                                        it('returns zero', async function () {
                                            const balance = await erc20Token.balanceOf(anotherAccount);
                                            assert.equal(balance, 0);
                                        });
                                    });

                                    describe('when the requested account has some tokens', function () {
                                        it('returns the total amount of tokens', async function () {
                                            const balance = await erc20Token.balanceOf(erc20Owner);
                                            assert.equal(balance, 100);
                                        });
                                    });
                                });
                            });

                            describe('erc721 tokens', function () {
                                describe('totalSupply', function () {
                                    it('returns total erc721 token supply', async function () {
                                        const totalSupply = await erc721Token.totalSupply();
                                        totalSupply.should.eql(web3.utils.toBN(2));
                                        //totalSupply.should.be.bignumber.equal(2);
                                    });
                                });

                                describe('balanceOf', function () {
                                    describe('when the given address owns some erc721 tokens', function () {
                                        it('returns the amount of erc721 tokens owned by the given address', async function () {
                                            const balance = await erc721Token.balanceOf(creator);
                                            //balance.should.be.bignumber.equal(2);
                                            balance.should.eql(web3.utils.toBN(2));
                                        });
                                    });

                                    describe('when the given address does not own any erc721 tokens', function () {
                                        it('returns 0', async function () {
                                            let balance = await erc721Token.balanceOf(accounts[1]);
                                            //balance.should.be.bignumber.equal(0);
                                            balance.should.eql(web3.utils.toBN(0));

                                            balance = await erc721Token.balanceOf(wallet.address);
                                            //balance.should.be.bignumber.equal(0);
                                            balance.should.eql(web3.utils.toBN(0));
                                        });
                                    });
                                });
                            });

                            // ownership
                            // transfer some to contract owner
                            describe('when the contract owner owns erc20 & erc721 tokens', function () {
                                const amount = totalSupply / 2; //50

                                beforeEach(async function () {
                                    // erc 20 tokens
                                    await erc20Token.transfer(wallet.address, amount, { from: erc20Owner });

                                    const senderBalance = await erc20Token.balanceOf(erc20Owner);
                                    assert.equal(senderBalance, totalSupply - amount);

                                    const recipientBalance = await erc20Token.balanceOf(wallet.address);
                                    assert.equal(recipientBalance, amount);

                                    // erc 721 token
                                    await erc721Token.transferFrom(creator, wallet.address, firstTokenId, { from: creator });
                                });

                                describe('when the requested account has some erc20 tokens', function () {
                                    it('returns the total amount of erc20 tokens', async function () {
                                        const balance = await erc20Token.balanceOf(wallet.address);
                                        assert.equal(balance, amount);
                                    });
                                });

                                it('should say we own the erc721 token', async function () {

                                    const newOwner = await erc721Token.ownerOf(firstTokenId);
                                    newOwner.should.be.equal(wallet.address);

                                    const newOwnerBalance = await erc721Token.balanceOf(wallet.address);
                                    newOwnerBalance.should.eql(web3.utils.toBN("1"));

                                    const previousOwnerBalance = await erc721Token.balanceOf(creator);
                                    previousOwnerBalance.should.eql(web3.utils.toBN("1"));
                                });

                                // do ETH, ERC20 and ERC721 transfer in one TX!
                                describe('when the contract owner transfers Ξ, erc20 and erc721 tokens via multisend with revert = 0', function () {

                                    const erc20Recipient = accounts[3];
                                    const erc721Recipient = accounts[4];
                                    const ethRecipient = utils.newKeyPair().address;
                                    let ethRecipientOrigBalance;
                                    const transferAmount = web3.utils.toWei("10000", 'wei');

                                    beforeEach(async function () {

                                        ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));

                                        // to (20), value (32), data length (32), data
                                        let dataArr = [];
                                        let revertBuff = Buffer.alloc(1);
                                        // don't revert for now
                                        revertBuff.writeUInt8(0);
                                        dataArr.push(revertBuff);

                                        // transfer ETH
                                        // 'to' is not padded (20 bytes)
                                        dataArr.push(Buffer.from(ethRecipient.replace('0x', ''), 'hex')); // address as string
                                        // value (32 bytes)
                                        dataArr.push(utils.numToBuffer(transferAmount));
                                        //console.log("transferAmount: " + utils.numToBuffer(transferAmount).toString('hex'));
                                        // data length (0)
                                        dataArr.push(utils.numToBuffer(0));
                                        // transfer ERC20
                                        // to
                                        dataArr.push(Buffer.from(erc20Token.address.replace('0x', ''), 'hex')); // address as string
                                        // value (32 bytes)
                                        dataArr.push(utils.numToBuffer(0));
                                        // push data length
                                        const erc20Buff = walletutils.erc20Transfer(amount / 2, erc20Recipient);
                                        dataArr.push(utils.numToBuffer(erc20Buff.length))
                                        // push data
                                        dataArr.push(erc20Buff);

                                        // transfer kitty to random addr
                                        // data argument

                                        dataArr.push(Buffer.from(erc721Token.address.replace('0x', ''), 'hex')); // address as string
                                        // value (32 bytes)
                                        dataArr.push(utils.numToBuffer(0));
                                        // erc 721 data
                                        const erc721DataBuff = walletutils.erc721Transfer(firstTokenId, wallet.address, erc721Recipient);
                                        dataArr.push(utils.numToBuffer(erc721DataBuff.length));
                                        dataArr.push(erc721DataBuff);
                                        // concat all buffers
                                        //console.log('data: 0x' + Buffer.concat(dataArr).toString('hex'));

                                        const gas = await walletutils.transact0(
                                            Buffer.concat(dataArr),
                                            wallet,
                                            cosignerPublicKey
                                        );

                                        logGasPrice(wtype, INVOKE0, TRANSFER_MULTI, gas);
                                    });

                                    afterEach(function () {
                                        // add sum in there
                                        let gp = getGasPrice(walletutils.WALLET_REGULAR, BASE);
                                        let g1 = gp[TRANSFER_ETH];
                                        g1 += gp[TRANSFER_ERC20];
                                        g1 += gp[TRANSFER_ERC721];
                                        logGasPrice(walletutils.WALLET_REGULAR, BASE, TRANSFER_MULTI, g1);
                                        console.table(gasPrices);
                                    });

                                    // Multisend
                                    it('should report correct erc20 and erc721 token and Ξ balances', async function () {

                                        // check ETH balances
                                        checkBalances(
                                            transferAmount,
                                            fundAmount,
                                            wallet.address,
                                            ethRecipient,
                                            ethRecipientOrigBalance
                                        );

                                        // check the ERC20 token balances
                                        const senderBalance = await erc20Token.balanceOf(erc20Owner);
                                        assert.equal(senderBalance, totalSupply - amount);

                                        const contractBalance = await erc20Token.balanceOf(wallet.address);
                                        //console.log(contractBalance);
                                        assert.equal(contractBalance, amount / 2);

                                        const recipientBalance = await erc20Token.balanceOf(erc20Recipient);
                                        assert.equal(recipientBalance, amount / 2);

                                        // check eth balances to be sure no weirdness happened
                                        let erc20RecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(erc20Recipient));

                                        let tBig = web3.utils.toBN(transferAmount);
                                        let remaining = (web3.utils.toBN(fundAmount)).sub(tBig);
                                        // left in wallet
                                        web3.utils.toBN(await web3.eth.getBalance(wallet.address)).eq(remaining).should.eql(true);
                                        // recipeintAmount
                                        let recipAmt = web3.utils.toBN(await web3.eth.getBalance(erc20Recipient));
                                        // reciever amount
                                        recipAmt.eq(erc20RecipientOrigBalance).should.eql(true);

                                        // ERC721
                                        const newOwner = await erc721Token.ownerOf(firstTokenId);
                                        newOwner.should.be.equal(erc721Recipient);

                                        const newOwnerBalance = await erc721Token.balanceOf(erc721Recipient);
                                        newOwnerBalance.eq(web3.utils.toBN("1")).should.eql(true);

                                        const previousOwnerBalance = await erc721Token.balanceOf(wallet.address);
                                        previousOwnerBalance.eq(web3.utils.toBN("0")).should.eql(true);

                                        // check eth balances to be sure no weirdness happened
                                        let erc721RecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(erc721Recipient));

                                        tBig = web3.utils.toBN(transferAmount);
                                        remaining = (web3.utils.toBN(fundAmount)).sub(tBig);
                                        // left in wallet
                                        web3.utils.toBN(await web3.eth.getBalance(wallet.address)).eq(remaining).should.eql(true);
                                        // recipeintAmount
                                        recipAmt = web3.utils.toBN(await web3.eth.getBalance(erc721Recipient));
                                        // reciever amount
                                        recipAmt.eq(erc721RecipientOrigBalance).should.eql(true);
                                    });
                                });

                                // do ETH, ERC20 and ERC721 transfer in one TX!
                                describe('when the contract owner transfers Ξ, erc20 and erc721 tokens via multisend with revert = 1', function () {

                                    const erc20Recipient = accounts[3];
                                    const erc721Recipient = accounts[4];
                                    const ethRecipient = utils.newKeyPair().address;
                                    let ethRecipientOrigBalance;
                                    const transferAmount = web3.utils.toWei("10000", 'wei');

                                    beforeEach(async function () {

                                        ethRecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));

                                        // to (20), value (32), data length (32), data
                                        let dataArr = [];
                                        let revertBuff = Buffer.alloc(1);
                                        // revert flag
                                        revertBuff.writeUInt8(1);
                                        dataArr.push(revertBuff);

                                        // transfer ETH
                                        // 'to' is not padded (20 bytes)
                                        dataArr.push(Buffer.from(ethRecipient.replace('0x', ''), 'hex')); // address as string
                                        // value (32 bytes)
                                        dataArr.push(utils.numToBuffer(transferAmount));
                                        //console.log("transferAmount: " + utils.numToBuffer(transferAmount).toString('hex'));
                                        // data length (0)
                                        dataArr.push(utils.numToBuffer(0));
                                        // transfer ERC20
                                        // to
                                        dataArr.push(Buffer.from(erc20Token.address.replace('0x', ''), 'hex')); // address as string
                                        // value (32 bytes)
                                        dataArr.push(utils.numToBuffer(0));
                                        // push data length
                                        const erc20Buff = walletutils.erc20Transfer(amount / 2, erc20Recipient);
                                        dataArr.push(utils.numToBuffer(erc20Buff.length))
                                        // push data
                                        dataArr.push(erc20Buff);

                                        // transfer kitty to random addr
                                        // data argument

                                        dataArr.push(Buffer.from(erc721Token.address.replace('0x', ''), 'hex')); // address as string
                                        // value (32 bytes)
                                        dataArr.push(utils.numToBuffer(0));
                                        // erc 721 data
                                        const erc721DataBuff = walletutils.erc721Transfer(firstTokenId, wallet.address, erc721Recipient);
                                        dataArr.push(utils.numToBuffer(erc721DataBuff.length));
                                        dataArr.push(erc721DataBuff);
                                        // concat all buffers
                                        //console.log('data: 0x' + Buffer.concat(dataArr).toString('hex'));

                                        const gas = await walletutils.transact0(
                                            Buffer.concat(dataArr),
                                            wallet,
                                            cosignerPublicKey
                                        );

                                        logGasPrice(wtype, INVOKE0, TRANSFER_MULTI, gas);
                                    });

                                    afterEach(function () {
                                        // add sum in there
                                        let gp = getGasPrice(walletutils.WALLET_REGULAR, BASE);
                                        let g1 = gp[TRANSFER_ETH];
                                        g1 += gp[TRANSFER_ERC20];
                                        g1 += gp[TRANSFER_ERC721];
                                        logGasPrice(walletutils.WALLET_REGULAR, BASE, TRANSFER_MULTI, g1);
                                        console.table(gasPrices);
                                    });

                                    // Multisend
                                    it('should report correct erc20 and erc721 token and Ξ balances', async function () {

                                        // check ETH balances
                                        checkBalances(
                                            transferAmount,
                                            fundAmount,
                                            wallet.address,
                                            ethRecipient,
                                            ethRecipientOrigBalance
                                        );

                                        // check the ERC20 token balances
                                        const senderBalance = await erc20Token.balanceOf(erc20Owner);
                                        assert.equal(senderBalance, totalSupply - amount);

                                        const contractBalance = await erc20Token.balanceOf(wallet.address);
                                        //console.log(contractBalance);
                                        assert.equal(contractBalance, amount / 2);

                                        const recipientBalance = await erc20Token.balanceOf(erc20Recipient);
                                        assert.equal(recipientBalance, amount / 2);

                                        // check eth balances to be sure no weirdness happened
                                        let erc20RecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(erc20Recipient));

                                        let tBig = web3.utils.toBN(transferAmount);
                                        let remaining = (web3.utils.toBN(fundAmount)).sub(tBig);
                                        // left in wallet
                                        web3.utils.toBN(await web3.eth.getBalance(wallet.address)).eq(remaining).should.eql(true);
                                        // recipeintAmount
                                        let recipAmt = web3.utils.toBN(await web3.eth.getBalance(erc20Recipient));
                                        // reciever amount
                                        recipAmt.eq(erc20RecipientOrigBalance).should.eql(true);

                                        // ERC721
                                        const newOwner = await erc721Token.ownerOf(firstTokenId);
                                        newOwner.should.be.equal(erc721Recipient);

                                        const newOwnerBalance = await erc721Token.balanceOf(erc721Recipient);
                                        newOwnerBalance.eq(web3.utils.toBN("1")).should.eql(true);

                                        const previousOwnerBalance = await erc721Token.balanceOf(wallet.address);
                                        previousOwnerBalance.eq(web3.utils.toBN("0")).should.eql(true);

                                        // check eth balances to be sure no weirdness happened
                                        let erc721RecipientOrigBalance = web3.utils.toBN(await web3.eth.getBalance(erc721Recipient));

                                        tBig = web3.utils.toBN(transferAmount);
                                        remaining = (web3.utils.toBN(fundAmount)).sub(tBig);
                                        // left in wallet
                                        web3.utils.toBN(await web3.eth.getBalance(wallet.address)).eq(remaining).should.eql(true);
                                        // recipeintAmount
                                        recipAmt = web3.utils.toBN(await web3.eth.getBalance(erc721Recipient));
                                        // reciever amount
                                        recipAmt.eq(erc721RecipientOrigBalance).should.eql(true);
                                    });
                                });
                            });
                        });
                    });
                });
            });
        });
    });
};


contract('Wallet', async (accounts) => {

    before(function () {
        // 7 rows 
        gasPrices.push({ "action": "base cost" });
        gasPrices.push({ "action": "invoke0 regular" });
        gasPrices.push({ "action": "invoke1CosignerSends regular" });
        gasPrices.push({ "action": "invoke1SignerSends regular" });
        gasPrices.push({ "action": "invoke2 regular" });
        gasPrices.push({ "action": "invoke0 clone" });
        gasPrices.push({ "action": "invoke1CosignerSends clone" });
        gasPrices.push({ "action": "invoke1SignerSends clone" });
        gasPrices.push({ "action": "invoke2 clone" });
        gasPrices.push({ "action": "invoke0 regular 2" });
        gasPrices.push({ "action": "invoke1CosignerSends regular 2" });
        gasPrices.push({ "action": "invoke1SignerSends regular 2" });
        gasPrices.push({ "action": "invoke2 regular 2" });
        gasPrices.push({ "action": "invoke0 clone 2" });
        gasPrices.push({ "action": "invoke1CosignerSends clone 2" });
        gasPrices.push({ "action": "invoke1SignerSends clone 2" });
        gasPrices.push({ "action": "invoke2 clone 2" });
    });

    describe('wallet tests', function () {

        describe('concerning selector values', function () {
            const deploy = async function () {
                contract = await Selector.new();
            };

            beforeEach(async function () {
                await deploy();
            });

            it('should run the selector', async function () {
                // invoke selectors
                let result = await contract.invoke0Selector();
                console.log('invoke0Selector: ' + result.toString('hex'));

                result = await contract.invoke1CosignerSendsSelector();
                console.log('invoke1CosignerSendsSelector: ' + result.toString('hex'));

                result = await contract.invoke2Selector();
                console.log('invoke2Selector: ' + result.toString('hex'));

                // InvocationSuccess
                result = await contract.invocationSuccessSelector();
                console.log('invocationSuccessSelector: ' + result.toString('hex'));

                result = await contract.authorizedSelector();
                console.log('authorizedSelector: ' + result.toString('hex'));

                result = await contract.emergencyRecoverySelector();
                console.log('emergencyRecoverySelector: ' + result.toString('hex'));

                result = await contract.recoveryAddressChangedSelector();
                console.log('recoveryAddressChangedSelector: ' + result.toString('hex'));

                result = await contract.isValidSignatureSelector();
                console.log('isValidSignatureSelector: ' + result.toString('hex'));

            });
        });

        describe('concerning creation', function () {

            let masterKey;
            let adminKey;

            const create = async function (m, a, c) {
                // create the wallet
                // address authorized, address cosigner, address recovery
                return await FullWallet.new(a, c, m);
            };

            describe('when admin key is 0', function () {

                beforeEach(async function () {
                    masterKey = accounts[0];
                    adminKey = zeroAddress;
                });

                it('should fail to deploy', async function () {
                    await utils.expectThrow(
                        create(masterKey, adminKey, 0)
                    );
                });
            });

            // currently possible
            describe.skip('when master key is 0', function () {

                beforeEach(async function () {
                    masterKey = zeroAddress;
                    adminKey = accounts[0];
                });

                it('should fail to deploy', async function () {
                    await utils.expectThrow(
                        create(masterKey, adminKey, 0)
                    );
                });
            });

            describe('when master key is 0 and cosigner is not 0', function () {

                beforeEach(async function () {
                    masterKey = zeroAddress;
                    adminKey = accounts[0];
                });

                it('should not fail to deploy', async function () {

                    await FullWallet.new(adminKey, accounts[5], masterKey);
                });
            });

            describe('when master key is 0 and cosigner is 0', function () {

                beforeEach(async function () {
                    masterKey = zeroAddress;
                    adminKey = accounts[0];
                });

                it('should fail to deploy', async function () {

                    await utils.expectThrow(
                        create(masterKey, adminKey, 0)
                    );
                });
            });

            describe('when master key is same as admin key', function () {

                beforeEach(async function () {
                    masterKey = accounts[0];
                    adminKey = accounts[0];
                });

                it('should fail to deploy', async function () {
                    await utils.expectThrow(
                        create(masterKey, adminKey, adminKey)
                    );
                });
            });

            describe('when initial cosigning key contains metadata', function () {

                const metaData = web3.utils.toBN('0xDEADBEEFDEADBEEFDEADBEEF0000000000000000000000000000000000000000')
                let cosigningKey;
                let wallet;

                beforeEach(async function () {
                    masterKey = utils.newKeyPair().address;
                    adminKey = accounts[1];
                    cosigningKey = metaData.add(web3.utils.toBN(accounts[2]));

                    wallet = await create(masterKey, adminKey, cosigningKey);
                });

                describe('when wallet is funded', function () {
                    const fundAmount = web3.utils.toWei("100000000", "gwei");
                    const funder = accounts[3];

                    beforeEach(async function () {
                        await walletutils.fundAddress(funder, wallet.address, fundAmount);
                    });

                    it('should be able to do transactions', async function () {
                        // send eth or something
                        const ethRecipient = utils.newKeyPair().address;
                        let nonce = 0;
                        // send ETH
                        await walletutils.transact1(walletutils.txData(
                            1, // revert (stricter)
                            ethRecipient,
                            web3.utils.toWei("1", 'kwei'),
                            Buffer.from('')
                        ), wallet, nonce,
                            { address1: adminKey, private1: privateKeys[1] },
                            accounts[2]
                        );

                        let newBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                        newBalance.eq(web3.utils.toBN(web3.utils.toWei("1", 'kwei'))).should.eql(true);

                        // increment nonce
                        nonce += 1;
                        // call transact11
                        await walletutils.transact11(walletutils.txData(
                            1, // revert (stricter)
                            ethRecipient,
                            web3.utils.toWei("1", 'kwei'),
                            Buffer.from('')
                        ), wallet, nonce,
                            { address1: accounts[2], private1: privateKeys[2] },
                            adminKey
                        );

                        newBalance = web3.utils.toBN(await web3.eth.getBalance(ethRecipient));
                        newBalance.eq(web3.utils.toBN(web3.utils.toWei("2", 'kwei'))).should.eql(true);

                    });

                });
            });
        });

        describe('concerning create2', function () {
            let walletFactory;
            //let cloneAddress;
            const masterPublicKey = accounts[8];
            const adminPublicKey = accounts[7];
            let cosignerPublicKey = accounts[5];
            // cannot add more than 0x4000000, see https://github.com/ethereum/web3.js/issues/2171 and https://github.com/indutny/bn.js/issues/176
            const metaData = web3.utils.toBN("0").add(web3.utils.toBN('0xDEADBEEFDEADBEEFDEADBEEF0000000000000000000000000000000000000000', 16));
            // create2 salt
            const salt = '0x' + crypto.randomBytes(32).toString('hex');
            const fullCosignerKey = metaData.add(web3.utils.toBN(cosignerPublicKey));

            beforeEach(async function () {
                var res = await walletutils.createCloneFactory()
                walletFactory = res[0];
                // cloneAddress = res[1];
                //console.log('walletFactory: ' + walletFactory.address);
            });

            it('should revert when deploying the same hash twice with clone', async function () {
                // await testSuite(walletutils.WALLET_CLONE, accounts, walletFactory, cloneAddress);

                const walletClone = await walletutils.createWallet(
                    walletutils.WALLET_CLONE_2,
                    masterPublicKey,
                    adminPublicKey,
                    fullCosignerKey,
                    walletFactory,
                    salt
                );

                expect(walletClone.address.length).to.be.above(0);
                // should throw, as this is the same salt
                await utils.expectThrow(
                    walletutils.createWallet(
                        walletutils.WALLET_CLONE_2,
                        masterPublicKey,
                        adminPublicKey,
                        fullCosignerKey,
                        walletFactory,
                        salt
                    )
                );

            });

            it('should revert when deploying the same hash twice with full', async function () {

                // try with full wallet
                const walletFull = await walletutils.createWallet(
                    walletutils.WALLET_REGULAR_2,
                    masterPublicKey,
                    adminPublicKey,
                    fullCosignerKey,
                    walletFactory,
                    salt
                );

                expect(walletFull.address.length).to.be.above(0);

                await utils.expectThrow(
                    walletutils.createWallet(
                        walletutils.WALLET_REGULAR_2,
                        masterPublicKey,
                        adminPublicKey,
                        fullCosignerKey,
                        walletFactory,
                        salt
                    )
                );

            });

            it('should revert if trying to deploy bad config of vars for clone 2', async function () {
                // use some bad vars
                await utils.expectThrow(
                    walletutils.createWallet(
                        walletutils.WALLET_CLONE_2,
                        masterPublicKey,
                        zeroAddress,
                        fullCosignerKey,
                        walletFactory,
                        salt
                    )
                );

                // try again with good vars
                const walletClone = await walletutils.createWallet(
                    walletutils.WALLET_CLONE_2,
                    masterPublicKey,
                    adminPublicKey,
                    fullCosignerKey,
                    walletFactory,
                    salt
                );

                expect(walletClone.address.length).to.be.above(0);
            });

            it('should revert if trying to deploy bad config of vars for full 2', async function () {
                // try with bad vars
                await utils.expectThrow(
                    walletutils.createWallet(
                        walletutils.WALLET_REGULAR_2,
                        masterPublicKey,
                        zeroAddress,
                        fullCosignerKey,
                        walletFactory,
                        salt
                    )
                );

                // no need to test again here, as hash will be different
            });

        });

        // ERC 165 compatibility
        describe('concerning ERC165 compatibility', function () {

            describe('when queryable wallet is deployed', function () {

                const metaData = web3.utils.toBN('0xDEADBEEFDEADBEEFDEADBEEF0000000000000000000000000000000000000000', 16);
                let cosigningKey;
                let wallet;

                beforeEach(async function () {
                    masterKey = utils.newKeyPair().address;
                    adminKey = accounts[1];
                    cosigningKey = metaData.add(web3.utils.toBN(accounts[2], 16));
                    // create the wallet
                    // address authorized, address cosigner, address recovery
                    wallet = await QueryableWallet.new(adminKey, cosigningKey, masterKey);
                });

                describe('when checker is deployed', function () {
                    let checker;
                    let addrs;

                    beforeEach(async function () {
                        checker = await ERC165Checker.new();
                    });

                    describe('when interface ids are correct', function () {
                        beforeEach(function () {
                            const ERC721_RECEIVED_FINAL = "0x150b7a02";
                            const ERC721_RECEIVED_DRAFT = "0xf0b9e5ba";
                            const ERC223_ID = "0xc0ee0b8a";
                            const ERC165_ID = "0x01ffc9a7"
                            const ERC1271_VS = "0x1626ba7e";
                            addrs = [ERC721_RECEIVED_FINAL, ERC721_RECEIVED_DRAFT, ERC223_ID, ERC165_ID, ERC1271_VS];
                        });

                        it('should return true for the interfaces it implements', async function () {
                            const result = await checker.checkInterfaces(wallet.address, addrs);
                            result.should.eql(true);
                        });
                    });

                    describe('when interface ids are not correct', function () {
                        beforeEach(function () {
                            const RANDO = "0xa0b9e5ba";
                            addrs = [RANDO];
                        });

                        it('should return false for the interfaces it implements', async function () {
                            const result = await checker.checkInterfaces(wallet.address, addrs);
                            result.should.eql(false);
                        });
                    });
                });

            });
        });

        describe('base costs', function () {
            it('should be able to send eth', async function () {
                // send eth from one account to another
                const transferAmount = web3.utils.toWei("10", 'wei');

                let result = await web3.eth.sendTransaction({
                    from: accounts[0],
                    to: accounts[1],
                    value: transferAmount
                });

                const receipt = await web3.eth.getTransactionReceipt(result.transactionHash);
                logGasPrice(walletutils.WALLET_REGULAR, BASE, TRANSFER_ETH, receipt.gasUsed);
            });

            // do ERC20
            describe('with regards to erc20 tokens', function () {
                // TODO
                const erc20Owner = accounts[1];
                const anotherAccount = accounts[2];
                const totalSupply = 100
                let token;

                describe('when the erc20 token contract is created', function () {

                    beforeEach(async function () {
                        token = await StandardTokenMock.new(erc20Owner, totalSupply);
                    });

                    // basic tests to verify the contracts working
                    describe('when asked for the total token supply', function () {

                        it('returns the total amount of tokens', async function () {
                            const total = await token.totalSupply();
                            assert.equal(totalSupply, total);
                        });
                    });

                    describe('when asked for the balanceOf', function () {

                        describe('when the requested account has no tokens', function () {
                            it('returns zero', async function () {
                                const balance = await token.balanceOf(anotherAccount);
                                assert.equal(balance, 0);
                            });
                        });

                        describe('when the requested account has some tokens', function () {
                            it('returns the total amount of tokens', async function () {
                                const balance = await token.balanceOf(erc20Owner);
                                assert.equal(balance, totalSupply);
                            });
                        });
                    });

                    // transfer some to contract owner
                    describe('when the initial recipient owns erc20 tokens', function () {
                        const amount = totalSupply / 2; //50

                        const initialErc20Recipient = accounts[4];

                        beforeEach(async function () {
                            await token.transfer(initialErc20Recipient, amount, { from: erc20Owner });

                            const senderBalance = await token.balanceOf(erc20Owner);
                            assert.equal(senderBalance, totalSupply - amount);

                            const recipientBalance = await token.balanceOf(initialErc20Recipient);
                            assert.equal(recipientBalance, amount);
                        });

                        describe('when the requested account has some tokens', function () {
                            it('returns the total amount of tokens', async function () {
                                const balance = await token.balanceOf(initialErc20Recipient);
                                assert.equal(balance, amount);
                            });
                        });

                        describe('when the initial recipient transfers erc20 tokens', function () {

                            const erc20Recipient = utils.newKeyPair().address;

                            describe('directly', function () {

                                beforeEach(async function () {
                                    // skip one to warm up blockchain state
                                    await token.transfer(erc20Recipient, amount / 2, { from: initialErc20Recipient });
                                    // initialized state
                                    const result = await token.transfer(erc20Recipient, amount / 2, { from: initialErc20Recipient });

                                    //console.log(result.receipt.gasUsed);

                                    logGasPrice(walletutils.WALLET_REGULAR, BASE, TRANSFER_ERC20, result.receipt.gasUsed);
                                });

                                it('should report correct erc20 token and Ξ balances', async function () {

                                    // check the token balances
                                    const senderBalance = await token.balanceOf(erc20Owner);
                                    assert.equal(senderBalance, totalSupply - amount);

                                    const contractBalance = await token.balanceOf(initialErc20Recipient);
                                    //console.log(contractBalance.toString(10)); // 0x32
                                    assert.equal(contractBalance, 0);

                                    const recipientBalance = await token.balanceOf(erc20Recipient);
                                    //console.log(recipientBalance.toString(10)); // 0x32
                                    assert.equal(recipientBalance, amount);

                                    // check eth balances to be sure no weirdness happened
                                    //let erc20RecipientOrigBalance = web3.utils.toBN( await web3.eth.getBalance(erc20Recipient));

                                    // checkBalances(
                                    //     0,
                                    //     fundAmount,
                                    //     wallet.address,
                                    //     erc20Recipient,
                                    //     erc20RecipientOrigBalance
                                    // );
                                });
                            });

                        });
                    });
                });
            });

            // do ERC721
            describe('with regards to erc721', function () {
                const name = 'Non Fungible Token';
                const symbol = 'NFT';
                const firstTokenId = 100;
                const secondTokenId = 200;
                const creator = accounts[0];
                let token;
                const erc721Receiver = accounts[1];

                beforeEach(async function () {
                    token = await ERC721TokenMock.new(name, symbol, { from: creator });
                    await token.mint(creator, firstTokenId, { from: creator });
                    await token.mint(creator, secondTokenId, { from: creator });
                });


                describe('totalSupply', function () {
                    it('returns total token supply', async function () {
                        const totalSupply = await token.totalSupply();
                        totalSupply.should.eql(web3.utils.toBN(2));
                    });
                });

                describe('balanceOf', function () {
                    describe('when the given address owns some tokens', function () {
                        it('returns the amount of tokens owned by the given address', async function () {
                            const balance = await token.balanceOf(creator);
                            balance.should.eql(web3.utils.toBN(2));
                        });
                    });

                    describe('when the given address does not own any tokens', function () {
                        it('returns 0', async function () {
                            let balance = await token.balanceOf(accounts[1]);
                            balance.should.eql(web3.utils.toBN(0));

                            balance = await token.balanceOf(erc721Receiver);
                            balance.should.eql(web3.utils.toBN(0));
                        });
                    });
                });

                describe('when the contract owner owns an erc721 token', function () {

                    beforeEach(async function () {
                        // send to contract owner
                        await token.transferFrom(creator, erc721Receiver, firstTokenId, { from: creator });
                        await token.transferFrom(creator, erc721Receiver, secondTokenId, { from: creator });
                    });

                    it('should say we own the token', async function () {

                        const newOwner = await token.ownerOf(firstTokenId);
                        newOwner.should.be.equal(erc721Receiver);

                        const newOwnerBalance = await token.balanceOf(erc721Receiver);
                        newOwnerBalance.should.eql(web3.utils.toBN(2));

                        const previousOwnerBalance = await token.balanceOf(creator);
                        previousOwnerBalance.should.eql(web3.utils.toBN(0));
                    });

                    describe('when user transfers the token using transferFrom()', function () {

                        const recipient = utils.newKeyPair().address;

                        describe('directly', function () {

                            beforeEach(async function () {
                                // transfer kitty to random addr
                                let result = await token.transferFrom(erc721Receiver, recipient, firstTokenId, { from: erc721Receiver });
                                result = await token.transferFrom(erc721Receiver, recipient, secondTokenId, { from: erc721Receiver });
                                //console.log(result.receipt.gasUsed);

                                logGasPrice(walletutils.WALLET_REGULAR, BASE, TRANSFER_ERC721, result.receipt.gasUsed);
                            });

                            it('should say the new owner owns the token', async function () {

                                let newOwner = await token.ownerOf(firstTokenId);
                                newOwner.should.be.equal(recipient);

                                newOwner = await token.ownerOf(secondTokenId);
                                newOwner.should.be.equal(recipient);

                                const newOwnerBalance = await token.balanceOf(recipient);
                                newOwnerBalance.should.eql(web3.utils.toBN(2));

                                const previousOwnerBalance = await token.balanceOf(erc721Receiver);
                                previousOwnerBalance.should.eql(web3.utils.toBN(0));

                                // check eth balances to be sure no weirdness happened
                                // let erc721RecipientOrigBalance = web3.utils.toBN( await web3.eth.getBalance(recipient));

                            });
                        });

                    });
                });
            });
        });


        describe('when a wallet factory is created', function () {
            let walletFactory;
            let cloneAddress;

            beforeEach(async function () {
                var res = await walletutils.createCloneFactory()
                walletFactory = res[0];
                cloneAddress = res[1];
                //console.log('walletFactory: ' + walletFactory.address);
            });

            describe('when clone wallet is created', function () {

                it('should run the test suite', async function () {
                    await testSuite(walletutils.WALLET_CLONE, accounts, walletFactory, cloneAddress);
                });
            });

            describe('when regular wallet is created', function () {

                it('should run the test suite', async function () {
                    await testSuite(walletutils.WALLET_REGULAR, accounts, walletFactory, cloneAddress);
                });
            });

            describe('when clone2 wallet created', function () {

                it('should run the test suite', async function () {
                    await testSuite(walletutils.WALLET_CLONE_2, accounts, walletFactory, cloneAddress);
                });
            });

            describe('when full 2 wallet created', function () {

                it('should run the test suite', async function () {
                    await testSuite(walletutils.WALLET_REGULAR_2, accounts, walletFactory, cloneAddress);
                });
            });

        });

    });

});
