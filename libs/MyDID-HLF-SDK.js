const express = require("express");
const router = express.Router();
const FabricCAServices = require('fabric-ca-client');
const { FileSystemWallet, X509WalletMixin, Gateway } = require('fabric-network');
const fs = require('fs');
const path = require('path');

const ccpPath = path.resolve(process.cwd(), 'HLF-SDK', 'connection_config.json');
const ccpJSON = fs.readFileSync(ccpPath, 'utf8');
const ccp = JSON.parse(ccpJSON);
const walletPath = path.join(process.cwd(), 'wallet');
const wallet = new FileSystemWallet(walletPath);
const gateway = new Gateway();

class chain {
    query = async (id) => {
        try {
            await gateway.connect(ccp, { wallet, identity: 'user1', discovery: { enabled: false } });
            const network = await gateway.getNetwork('mychannel');
            const contract = network.getContract('mydid');
            const result = await contract.evaluateTransaction('query', id);
            const a = result.toString('utf-8');
            return a;
        } catch (error) {
            return error;
        }
    }

    insert = async (id, key) => {
        try {
            await gateway.connect(ccp, { wallet, identity: 'user1', discovery: { enabled: false } });
            const network = await gateway.getNetwork('mychannel');
            const contract = network.getContract('mydid');
            const result = await contract.submitTransaction('insert', id, key);
            return `Transaction has been evaluated, result is: ${result.toString()}`;
        } catch (error) {
            console.error(`Failed to evaluate transaction: ${error}`);
            return error;
        }
    }

    changepk = async (id, key) => {
        try {
            await gateway.connect(ccp, { wallet, identity: 'user1', discovery: { enabled: false } });
            const network = await gateway.getNetwork('mychannel');
            const contract = network.getContract('mydid');
            const result = await contract.submitTransaction('changepk', id, key);
            return `Transaction has been evaluated, result is: ${result.toString()}`;
        } catch (error) {
            return error
        }
    }

    deleteid = async (id) => {
        try {
            await gateway.connect(ccp, { wallet, identity: 'user1', discovery: { enabled: false } });
            const network = await gateway.getNetwork('mychannel');
            const contract = network.getContract('mydid');
            const result = await contract.submitTransaction('delete', id);
            return `Transaction has been evaluated, result is: ${result.toString()}`;
        } catch (error) {
            return error
        }
    }
}

module.exports = new chain;