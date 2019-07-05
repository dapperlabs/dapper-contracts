const abi = require("ethereumjs-abi");
const BN = require("bn.js");
const Promise = require("bluebird");
const crypto = require("crypto");
const ethUtils = require("ethereumjs-util");

const getBalanceWei = async address => {
  return web3.utils.toBN(await web3.eth.getBalance(address));
};

// Polls an array for changes
const waitForEvents = (eventsArray, numEvents) => {
  if (numEvents === 0) {
    return Promise.delay(1000); // Wait a reasonable amount so the caller can know no events fired
  }
  numEvents = numEvents || 1;
  const oldLength = eventsArray.length;
  let numTries = 0;
  const pollForEvents = function () {
    numTries++;
    if (eventsArray.length >= oldLength + numEvents) {
      return;
    }
    if (numTries >= 100) {
      if (eventsArray.length == 0) {
        console.log("Timed out waiting for events!");
      }
      return;
    }
    return Promise.delay(50).then(pollForEvents);
  };
  return pollForEvents();
};

const expectThrow = async promise => {
  try {
    await promise;
  } catch (error) {
    // TODO: Check jump destination to distinguish between a throw
    //       and an actual invalid jump.
    const invalidOpcode = error.message.search("invalid opcode") >= 0;
    // TODO: When we contract A calls contract B, and B throws, instead
    //       of an 'invalid jump', we get an 'out of gas' error. How do
    //       we distinguish this from an actual out of gas event? (The
    //       ganache log actually show an 'invalid jump' event.)
    const outOfGas = error.message.search("out of gas") >= 0;
    const revert = error.message.search("revert") >= 0;
    assert(
      invalidOpcode || outOfGas || revert,
      "Expected throw, got '" + error + "' instead"
    );
    return;
  }
  assert.fail("Expected throw not received");
};

/**
 * Helper to get sha3 for solidity tightly-packed arguments
 * Actually signing `EIP191_PREFIX, EIP191_VERSION_DATA, walletAddress(this), nonce, authorizedAddress, data`
 * @param {string} walletAddr address of wallet
 * @param {number} nonce the nonce
 * @param {string} authorizedAddress the authorization key address 
 * @param {string} data data as a hex string
 */
const getSha3ForConfirmationTx = (walletAddr, nonce, authorizedAddress, data) => {
  return abi.soliditySHA3(
    ['int8', 'int8', 'address', 'uint256', 'address', 'string'],
    [0x19, 0x0, new BN(walletAddr.replace('0x', ''), 16), nonce, new BN(authorizedAddress.replace('0x', ''), 16), data]
  );
};

const funcHash = signature => {
  return abi.soliditySHA3(["string"], [signature]).slice(0, 4);
};

/**
 * Helper to get sha3 for solidity tightly-packed arguments
 * Actually signing `EIP191_PREFIX, EIP191_VERSION_DATA, walletAddress(this), data`
 * @param {string} walletAddr address of wallet
 * @param {Buffer} hash hashed data
 */
const getSha3ForERC1271 = (walletAddr, hash) => {
  return abi.soliditySHA3(
    ['int8', 'int8', 'address', 'bytes32'],
    [0x19, 0x0, new BN(walletAddr.replace('0x', ''), 16), hash]
  );
};

/**
 * Converts a number to a 32 byte padded hex encoded buffer
 * @param {number | string} num 
 * @returns {Buffer} buffer
 */
const numToBuffer = num => {
  return numToBufferWithN(num, 64);
};

const numToBufferWithN = (num, amt) => {
  return Buffer.from(
    new BN(web3.utils.toHex(num).replace("0x", ""), 16).toString(16, amt),
    "hex"
  ); // number
};

/**
 * Pads a bytes4, encoded as a hex string, to 32 bytes.
 * The output is a hex-encoded string.
 */
const padBytes4 = b => `${b}${'0'.repeat(64-4*2)}`;

/**
 * 
 * @param {number | string | BigNumber} num 
 */
const asAddressString = num => {
  //0x0000000000000000deadbeefdeadbeefdeadbeef2932b7a2355d6fecc4b5c0b6bd44cc31df247a2e
  let str = new BN(web3.utils.toHex(num).replace("0x", ""), 16).toString(
    16,
    40
  );
  if (str.length > 40) {
    str = str.slice(-40);
  }
  return web3.utils.toChecksumAddress("0x" + str);
};

// Serialize signature into format understood by our recoverAddress function
const serializeSignature = ({ r, s, v }) =>
  "0x" + Buffer.concat([r, s, Buffer.from([v])]).toString("hex");

const serializeSignatures = (sig1, sig2) =>
  "0x" +
  Buffer.concat([
    sig1.r,
    sig1.s,
    Buffer.from([sig1.v]),
    sig2.r,
    sig2.s,
    Buffer.from([sig2.v])
  ]).toString("hex");

// splits the signatures into their three parts
const splitSignatures = (sig1, sig2) => {
  if (sig2) {
    return [
      ["0x" + sig1.r.toString("hex"), "0x" + sig2.r.toString("hex")],
      ["0x" + sig1.s.toString("hex"), "0x" + sig2.s.toString("hex")],
      [
        "0x" + Buffer.from([sig1.v]).toString("hex"),
        "0x" + Buffer.from([sig2.v]).toString("hex")
      ]
    ];
  } else {
    return [
      ["0x" + sig1.r.toString("hex"), "0x00000000"],
      ["0x" + sig1.s.toString("hex"), "0x00000000"],
      ["0x" + Buffer.from([sig1.v]).toString("hex"), "0x0"]
    ];
  }
};

const printLogs = result => {
  for (log of result.logs) {
    if (log.args.value) {
      console.log(
        'log: {"label": ' +
          log.args.label +
          ', "value": 0x' +
          log.args.value.toString(16) +
          "}"
      );
    } else {
      console.log("log: " + JSON.stringify(log.args));
    }
  }
};

/**
 * @returns {object} object with 'private' (`Buffer`) and 'address' (0x prefixed hex `string` address) components
 */
const newKeyPair = () => {
  const private = crypto.randomBytes(32);
  const address = "0x" + ethUtils.privateToAddress(private).toString("hex");
  return {
    address: web3.utils.toChecksumAddress(address),
    private: private
  };
};

// deterministically computes the smart contract address given
// the account the will deploy the contract (factory contract)
// the salt as uint256 and the contract bytecode
// As seen here: https://github.com/miguelmota/solidity-create2-example
const buildCreate2Address = function (creatorAddress, saltHex, byteCode) {
  return `0x${web3.utils.sha3(`0x${[
    'ff',
    creatorAddress,
    saltHex,
    web3.utils.sha3(byteCode)
  ].map(x => x.replace(/0x/, ''))
  .join('')}`).slice(-40)}`.toLowerCase()
}

module.exports = {
  waitForEvents,
  expectThrow,
  getSha3ForConfirmationTx,
  getSha3ForERC1271,
  //getSha3ForConfirmationTxCallData,
  serializeSignature,
  serializeSignatures,
  splitSignatures,
  funcHash,
  // addrToBuffer,
  numToBuffer,
  numToBufferWithN,
  printLogs,
  newKeyPair,
  asAddressString,
  getBalanceWei,
  buildCreate2Address,
  padBytes4 
};
