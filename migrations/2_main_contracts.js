// /**
//  * These are not strictly needed for tests; however since the tests
//  * run deployments anyways it is nice to know that the contracts deploy, as 
//  * it seems there are issues you can unearth when attempting to deploy
//  */

var WalletFactory = artifacts.require("./WalletFactory/WalletFactory.sol");
var CloneableWallet = artifacts.require('./Wallet/CloneableWallet.sol');


module.exports = function (deployer) {

    deployer.deploy(CloneableWallet).then(() => {

        return deployer.deploy(WalletFactory, CloneableWallet.address);
    });
};
