/*
 * NB: since truffle-hdwallet-provider 0.0.5 you must wrap HDWallet providers in a
 * function when declaring them. Failure to do so will cause commands to hang. ex:
 * ```
 * mainnet: {
 *     provider: function() {
 *       return new HDWalletProvider(mnemonic, 'https://mainnet.infura.io/<infura-key>')
 *     },
 *     network_id: '1',
 *     gas: 4500000,
 *     gasPrice: 10000000000,
 *   },
 */

require("dotenv").config();

const web3 = require("web3");
const HDWalletProvider = require("truffle-hdwallet-provider");

const {
  ETH_NODE_ADDRESS,
  ETH_NODE_USER,
  ETH_NODE_PASSWORD,
  ETH_FROM_ADDRESS,
  HD_MNEMONIC,
  INFURA_API_KEY
} = process.env;

function getProvider() {
  return new web3.providers.HttpProvider(
    ETH_NODE_ADDRESS,
    10000,
    ETH_NODE_USER,
    ETH_NODE_PASSWORD
  );
}

function getHDProvider() {
  return new HDWalletProvider(
    HD_MNEMONIC,
    "https://rinkeby.infura.io/v3/" + INFURA_API_KEY
  );
}

module.exports = {
  // See <http://truffleframework.com/docs/advanced/configuration>
  // to customize your Truffle configuration!
  networks: {
    // development: {
    //   host: "127.0.0.1",
    //   port: 8545,
    //   gas: 4500000, // Gas limit used for deploys
    //   gasPrice: 10000000000,
    //   network_id: "*" // Match any network id
    // },
    // development: {
    //   host: "127.0.0.1",
    //   port: 9545,
    //   gas: 45000000, // Gas limit used for deploys
    //   gasPrice: 10000000000,
    //   network_id: "*" // Match any network id
    // },

    // this is rinkeby for our geth node
    rinkeby_geth: {
      provider: getProvider,
      network_id: 4,
      from: ETH_FROM_ADDRESS,
      gas: 4500000, // 2M gas limit used for deploy
      gasPrice: 10000000000 // 10gwei
    },
    rinkeby_local: {
      provider: getHDProvider,
      network_id: 4,
      gas: 4500000, // 2M gas limit used for deploy
      gasPrice: 10000000000 // 10gwei
    },
    live: {
      provider: getProvider,
      network_id: 1,
      from: ETH_FROM_ADDRESS,
      gas: 1000000, // 1M
      gasPrice: 5000000000 // 5 gwei
    }
  },
  solc: {
    optimizer: {
      enabled: true,
      runs: 200
    }
  },
  // https://truffle.readthedocs.io/en/beta/advanced/configuration/
  mocha: {
    bail: true
  },
  compilers: {
    solc: {
      version: "0.5.10",
      settings: {
        evmVersion: "constantinople",
        optimizer: {
          enabled: true,
          runs: 200
        }
      }
    }
  }
};
