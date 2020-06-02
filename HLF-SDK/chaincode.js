/*
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
*/

const shim = require('fabric-shim');
const util = require('util');

var Chaincode = class {

    // Initialize the chaincode
    async Init(stub) {
        console.info('========= mydid Init =========');
        return shim.success();
    }

    async Invoke(stub) {
        let ret = stub.getFunctionAndParameters();
        console.info(ret);
        let method = this[ret.fcn];
        if (!method) {
            console.log('no method of name:' + ret.fcn + ' found');
            return shim.success();
        }
        try {
            let payload = await method(stub, ret.params);
            return shim.success(payload);
        } catch (err) {
            console.log(err);
            return shim.error(err);
        }
    }

    async changepk(stub, args) {
        if (args.length != 2) {
            throw new Error('Incorrect number of arguments. Expecting 3');
        }

        let id = args[0];
        let newpk = args[1];

        // Get the state from the ledger
        let pk = await stub.getState(id);
        if (!pk) {
            throw new Error('Invalid Id');
        }

        console.info(util.format('id = %d, newpk = %d\n', id, newpk));

        // Write the states back to the ledger
        await stub.putState(id, Buffer.from(newpk));

    }

    // Deletes an entity from state
    async delete(stub, args) {
        if (args.length != 1) {
            throw new Error('Incorrect number of arguments. Expecting 1');
        }

        let id = args[0];

        // Delete the key from the state in ledger
        await stub.deleteState(id);
    }

    // query callback representing the query of a chaincode
    async query(stub, args) {
        if (args.length != 1) {
            throw new Error('Incorrect number of arguments. Expecting name of the person to query')
        }

        let jsonResp = {};
        let id = args[0];

        // Get the state from the ledger
        let idvalbytes = await stub.getState(id);
        if (!idvalbytes) {
            jsonResp.error = 'Failed to get state for ' + id;
            throw new Error(JSON.stringify(jsonResp));
        }

        jsonResp.name = id;
        jsonResp.pk = idvalbytes.toString();
        console.info('Query Response:');
        console.info(jsonResp);
        return idvalbytes;
    }
    async insert(stub, args) {
        if (args.length != 2) {
            throw new Error('Incorrect number of arguments. Expecting 1')
        }

        let id = args[0];
        let npk = args[1];

        console.info(util.format('id = %d, newpk = %d\n', id, npk));

        // Write the states back to the ledger
        await stub.putState(id, Buffer.from(npk));
    }
};

shim.start(new Chaincode());