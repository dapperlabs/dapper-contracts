const utils = require("./utils");
const ethUtils = require("ethereumjs-util");

const WalletFactory = artifacts.require("./WalletFactory/WalletFactory.sol");
const CloneableWallet = artifacts.require("./Wallet/CloneableWallet.sol");
const FullWallet = artifacts.require("./Wallet/FullWallet.sol");

require("chai").should();

// wallet type
const WALLET_REGULAR = 0;
const WALLET_CLONE = 1;
const WALLET_REGULAR_2 = 2;
const WALLET_CLONE_2 = 3;


// chain id
const CHAIN_ID = 0;

/**
 * @returns {[WalletFactory, root]} a new WalletFactory instance and the clone address
 */
const createCloneFactory = async function () {
  const walletRoot = await CloneableWallet.new();
  const walletFactory = await WalletFactory.new(walletRoot.address);
  return [walletFactory, walletRoot.address];
};

/**
 * 
 * @param {*} wtype WALLET_CLONE or WALLET_REGULAR
 * @param {string} _master master key address - string in hex format
 * @param {string} _admin admin key address - string in hex format
 * @param {string} _cosigner cosigner address - string in hex format
 * @param {*} _walletFactory a WalletFactory
 * @param {string} _salt the salt to use to deploy the wallet
 * @returns {FullWallet} a fresh wallet
 */
const createWallet = async function (
  wtype,
  _master,
  _admin,
  _cosigner,
  _walletFactory,
  _salt
) {
  let _wallet;
  let code;
  switch (wtype) {
    case WALLET_CLONE:
      {
        const result = await _walletFactory.deployCloneWallet(
          _master,
          _admin,
          _cosigner
        );
        result.logs
          .filter(log => log.event === "WalletCreated")
          .forEach(log => {
            _wallet = CloneableWallet.at(log.args.wallet);
          });
        console.log("clone wallet gas used: " + result.receipt.gasUsed);
      }
      break;
    case WALLET_REGULAR:
      {
        const result = await _walletFactory.deployFullWallet(
          _master,
          _admin,
          _cosigner
        );
        result.logs
          .filter(log => log.event === "WalletCreated")
          .forEach(log => {
            _wallet = FullWallet.at(log.args.wallet);
          });
        console.log("full wallet gas used: " + result.receipt.gasUsed);
      }
      break;
    case WALLET_CLONE_2:
      {
          const result = await _walletFactory.deployCloneWallet2(
            _master,
            _admin,
            _cosigner,
            _salt
          );
          result.logs
            .filter(log => log.event === "WalletCreated")
            .forEach(log => {
              _wallet = CloneableWallet.at(log.args.wallet);
            });
          console.log("clone2 wallet gas used: " + result.receipt.gasUsed);
      }
      break;
    case WALLET_REGULAR_2:
      {
        const result = await _walletFactory.deployFullWallet2(
          _master,
          _admin,
          _cosigner,
          _salt
        );

        result.logs
          .filter(log => log.event === "WalletCreated")
          .forEach(log => {
            _wallet = FullWallet.at(log.args.wallet);
          });
        console.log("full wallet gas used: " + result.receipt.gasUsed);
      }
      break;
  }

  return _wallet;
};

/**
 * 
 * @param {number | string} _funder the funding address
 * @param {number | string} _to the receiver of the funds
 * @param {string} _amount the amount in wei
 */
const fundAddress = async function (_funder, _to, _amount) {
  await web3.eth.sendTransaction({
    from: _funder,
    to: _to,
    value: _amount
  });
  const toBalAfter = await web3.eth.getBalance(_to);
  toBalAfter.should.eql(_amount);
};

/**
 * 
 * @param {FullWallet} _wallet the wallet object
 * @param {number | string} _key the public address to get the nonce for
 * @returns {number} the nonce
 */
const getNonce = async function (_wallet, _key) {
  // Run before each test. Sets the sequence ID up to be used in the tests
  return (await _wallet.nonces.call(_key)).toNumber();
};

/**
 * Calls a wallet with an arbitrary method ID
 * @param {FullWallet} _wallet the wallet to call
 * @param {string} _methodID The method ID of the method we're calling
 * @param {Buffer} _data The data to pass to the method, encoding the args
 */
const callDynamic = async function (_wallet, _methodID, _data) {
  let args = "";
  if (_data) {
    args = _data.toString("hex");
  };
  return (await web3.eth.call({
    to: _wallet.address,
    data: "0x" + _methodID + args,
  }));
}

/**
 * Sends a transaction to a wallet with an arbitrary method ID
 * @param {FullWallet} _wallet The wallet to call
 * @param {string} _from The sender of the transaction
 * @param {string} _methodID The method ID of the method we're calling
 * @param {Buffer} _data The data to pass to the method, encoding the args
 */
const transactDynamic = async function (_wallet, _from, _methodID, _data) {
  let args = "";
  if (_data) {
    args = _data.toString("hex");
  };
  return (await web3.eth.sendTransaction({
    to: _wallet.address,
    from: _from, 
    data: "0x" + _methodID + args,
  }));
}
 

/**
 * 
 * @param {Buffer} _data 
 * @param {FullWallet} _wallet 
 * @param {string} _sender string in hex format (must be address from accounts array)
 */
const transact0 = async function (_data, _wallet, _sender) {
  // call invoke0
  const result = await _wallet.invoke0("0x" + _data.toString("hex"), {
    from: _sender
  });

  //utils.printLogs(result);

  //console.log("sender: " + _sender);

  return result.receipt.gasUsed;
};

/**
 * 
 * @param {Buffer} _data 
 * @param {Wallet} _wallet 
 * @param {string} _sender string in hex format (must be address from accounts array)
 */
const transact0Twice = async function (_data, _wallet, _sender) {
  await transact0(_data, _wallet, _sender);
  const gas = await transact0(_data, _wallet, _sender);
  return gas;
};

/**
 * 
 * @param {Buffer} _data 
 * @param {FullWallet} _wallet 
 * @param {number} _nonce 
 * @param {*} param3 - private/public key pair (the signer)
 * @param {string} _sender - string in hex format (must be address from accounts array) (the cosigner)
 */
const transact1 = async function (
  _data,
  _wallet,
  _nonce,
  { address1, private1 },
  _sender
) {
  // get hash
  const operationHash = utils.getSha3ForConfirmationTx(
    _wallet.address,
    _nonce,
    address1,
    _data
  );

  //console.log("operationHash: 0x" + operationHash.toString('hex'));

  const sig1 = ethUtils.ecsign(operationHash, private1, CHAIN_ID);
  const r = "0x" + sig1.r.toString("hex");
  const s = "0x" + sig1.s.toString("hex");
  const v = "0x" + Buffer.from([sig1.v]).toString("hex");

  // console.log("r: " + r);
  // console.log("s: " + s);
  // console.log("v: " + v);

  // call invoke1CosignerSends
  const result = await _wallet.invoke1CosignerSends(
    v,
    r,
    s,
    _nonce,
    address1,
    '0x' + _data.toString('hex'),
    { from: _sender }
  );

  //utils.printLogs(result);

  //console.log("child key 1: " + address1);
  return result.receipt.gasUsed;
};

/**
 * 
 * @param {Buffer} _data 
 * @param {Wallet} _wallet 
 * @param {*} _nonce 
 * @param {*} param3 
 * @param {string} _sender 
 */
const transact1Twice = async function (
  _data,
  _wallet,
  _nonce,
  { address1, private1 },
  _sender
) {
  let nonce = _nonce;
  await transact1(_data, _wallet, nonce, { address1, private1 }, _sender);
  nonce += 1;
  let gas = await transact1(
    _data,
    _wallet,
    nonce,
    { address1, private1 },
    _sender
  );
  return gas;
};

/**
 * 
 * @param {Buffer} _data 
 * @param {Wallet} _wallet 
 * @param {*} _nonce 
 * @param {*} param3 - public/private key pair of the cosigner
 * @param {string} _sender - treated as the signer in this cae
 */
const transact11 = async function (
  _data,
  _wallet,
  _nonce,
  { address1, private1 },
  _sender
) {
  // get hash
  const operationHash = utils.getSha3ForConfirmationTx(
    _wallet.address,
    _nonce,
    _sender,
    _data
  );

  //console.log("operationHash: 0x" + operationHash.toString('hex'));

  const sig1 = ethUtils.ecsign(operationHash, private1, CHAIN_ID);
  const r = "0x" + sig1.r.toString("hex");
  const s = "0x" + sig1.s.toString("hex");
  const v = "0x" + Buffer.from([sig1.v]).toString("hex");

  // console.log("r: " + r);
  // console.log("s: " + s);
  // console.log("v: " + v);

  // call invoke1SignerSends (invoke11)
  const result = await _wallet.invoke1SignerSends(
    v,
    r,
    s,
    "0x" + _data.toString("hex"),
    { from: _sender }
  );

  //utils.printLogs(result);

  //console.log("child key 1: " + address1);
  return result.receipt.gasUsed;
};

/**
 * 
 * @param {Buffer} _data 
 * @param {Wallet} _wallet 
 * @param {*} _nonce 
 * @param {*} param3 
 * @param {string} _sender 
 */
const transact11Twice = async function (
  _data,
  _wallet,
  _nonce,
  { address1, private1 },
  _sender
) {
  let nonce = _nonce;
  await transact11(_data, _wallet, nonce, { address1, private1 }, _sender);
  nonce += 1;
  let gas = await transact11(
    _data,
    _wallet,
    nonce,
    { address1, private1 },
    _sender
  );
  return gas;
};

/**
 * 
 * @param {Buffer} _data 
 * @param {Wallet} _wallet 
 * @param {*} _nonce 
 * @param {*} param3 
 * @param {string} _sender 
 */
const transact2 = async function (
  _data,
  _wallet,
  _nonce,
  { address1, private1, address2, private2 },
  _sender
) {
  // get hash
  const operationHash = utils.getSha3ForConfirmationTx(
    _wallet.address,
    _nonce,
    address1,
    _data
  );

  //console.log("operationHash: 0x" + operationHash.toString('hex'));

  let r, s, v;
  const sig1 = ethUtils.ecsign(operationHash, private1, CHAIN_ID);
  const sig2 = ethUtils.ecsign(operationHash, private2, CHAIN_ID);
  [r, s, v] = utils.splitSignatures(sig1, sig2);

  const result = await _wallet.invoke2(
    v,
    r,
    s,
    _nonce,
    address1,
    '0x' + _data.toString('hex'),
    { from: _sender }
  );

  utils.printLogs(result);

  //console.log("child key 1: " + address1);
  //console.log("child key 2: " + address2);

  return result.receipt.gasUsed;
};

/**
 * 
 * @param {Buffer} _data - a data buffer
 * @param {Wallet} _wallet - the wallet contract instance
 * @param {*} _nonce - the initial wallet nonce
 * @param {*} param3 - the public and private key pairs
 * @param {string} _sender - signer of the outer transaction
 */
const transact2Twice = async function (
  _data,
  _wallet,
  _nonce,
  { address1, private1, address2, private2 },
  _sender
) {
  let nonce = _nonce;
  await transact2(
    _data,
    _wallet,
    nonce,
    { address1, private1, address2, private2 },
    _sender
  );
  // send again because the gas cost will change a bit
  nonce += 1;
  const gas = await transact2(
    _data,
    _wallet,
    nonce,
    { address1, private1, address2, private2 },
    _sender
  );
  return gas;
};

const erc20Transfer = (amount, erc20Recipient) => {
  let erc20DataArr = [];
  // function signature
  erc20DataArr.push(utils.funcHash("transfer(address,uint256)"));
  // arg: to address
  erc20DataArr.push(utils.numToBuffer(erc20Recipient));
  // arg: amount (256)
  erc20DataArr.push(utils.numToBuffer(amount));
  return Buffer.concat(erc20DataArr);
};

const erc721Transfer = (tokenID, walletAddress, recipient) => {
  let dataArr = [];
  // function signature
  dataArr.push(utils.funcHash("transferFrom(address,address,uint256)"));
  // arg: from address
  dataArr.push(utils.numToBuffer(walletAddress));
  // arg: to address
  dataArr.push(utils.numToBuffer(recipient));
  // arg: NFT index
  dataArr.push(utils.numToBuffer(tokenID));
  return Buffer.concat(dataArr);
};
/**
 * 
 * @param {number} revert : 1 (revert) or 0 (no revert)
 * @param {number | string} to 
 * @param {number | string} amount 
 * @param {Buffer} dataBuff 
 */
const txData = (revert, to, amount, dataBuff) => {
  // revert_flag (1), to (20), value (32), data length (32), data
  let dataArr = [];
  let revertBuff = Buffer.alloc(1);
  // don't revert for now
  revertBuff.writeUInt8(revert);
  dataArr.push(revertBuff);
  // 'to' is not padded (20 bytes)
  dataArr.push(Buffer.from(to.replace("0x", ""), "hex")); // address as string
  // value (32 bytes)
  dataArr.push(utils.numToBuffer(amount));
  // data length (0)
  dataArr.push(utils.numToBuffer(dataBuff.length));
  if (dataBuff.length > 0) {
    dataArr.push(dataBuff);
  }
  return Buffer.concat(dataArr);
};

module.exports = {
  WALLET_REGULAR,
  WALLET_CLONE,
  WALLET_CLONE_2,
  WALLET_REGULAR_2,
  CHAIN_ID,
  createCloneFactory,
  createWallet,
  fundAddress,
  getNonce,
  transact0,
  transact0Twice,
  transact1,
  transact1Twice,
  transact11,
  transact11Twice,
  transact2,
  transact2Twice,
  erc20Transfer,
  erc721Transfer,
  txData,
  callDynamic,
  transactDynamic
};
