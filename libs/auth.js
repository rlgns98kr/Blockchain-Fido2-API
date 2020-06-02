/*
 * @license
 * Copyright 2019 Google Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */
const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const { Fido2Lib } = require('fido2-lib');
const URL = require('url').URL;
const { coerceToBase64Url,
  coerceToArrayBuffer
} = require('fido2-lib/lib/utils');
const fs = require('fs');
const chain = require('./MyDID-HLF-SDK');

const low = require('lowdb');

if (!fs.existsSync('./.data')) {
  fs.mkdirSync('./.data');
}

const FileSync = require('lowdb/adapters/FileSync');
const adapter = new FileSync('.data/db.json');
const db = low(adapter);

router.use(express.json());

db.defaults({
  users: []
}).write();

var registerObjects = {
  '1234::1234': {
    id: 'yho.ddcdddo.d.m.com::112',
    username: '112',
    url: 'yho.com'
  }
};
var signinObjects = {
  '1234::1234': {
    id: 'yho.ddcdddo.d.m.com::112',
    username: '112',
    url: 'yho.com'
  }
}

router.use(express.json());


const f2l = new Fido2Lib({
  timeout: 30 * 1000 * 60,
  rpId: process.env.HOSTNAME,
  rpName: "MyDID",
  challengeSize: 32,
  cryptoParams: [-7]
});



const csrfCheck = (req, res, next) => {
  if (req.header('X-Requested-With') != 'XMLHttpRequest') {
    res.status(400).json({ error: 'invalid access.' });
    return;
  }
  next();
};

/**
* 사용자 정의 헤더`X-Requested-With`를 사용하여 CSRF 보호 확인
 * 쿠키에`username`이 포함되어 있지 않으면 사용자가 인증되지 않은 것으로 간주하십시오.
 * Checks CSRF protection using custom header `X-Requested-With`
 * If cookie doesn't contain `username`, consider the user is not authenticated.
 **/
const sessionCheck = (req, res, next) => {
  if (!req.cookies['signed-in']) {
    res.status(401).json({ error: 'not signed in.' });
    return;
  }
  next();
};

/**
* 사용자 이름을 확인하고 존재하지 않는 경우 새 계정을 만드십시오.
 `username` 쿠키를 설정하십시오.
  * Check username, create a new account if it doesn't exist.
 * Set a `username` cookie.
 **/

router.post('/register', (req, res) => {
  if (req.get('User-Agent').indexOf('okhttp') > -1) {
    res.status(400).send({ error: 'Bad request' });
    return;
  } else {
    const username = req.body.username;
    const urlimsi = new URL(req.headers.origin);
    const url = urlimsi.hostname;
    const registerNumber = req.body.registerNumber;
    const registerObjectId = username + '::' + registerNumber;
    if (url && urlimsi && registerNumber && !registerObjects[registerObjectId]) {
      registerObjects[registerObjectId] = {
        id: url + '::' + username,
        username: username,
        url: url
      }
      res.json({ message: '5분안에 MyDID 앱에서 등록절차를 마무리하신 후 확인 버튼을 눌러주세요.' });
      console.log(registerObjectId, url);
      setTimeout(() => {
        delete registerObjects[registerObjectId];
      }, 300000);
    }
    else {
      res.json({ message: '다른 인증 번호를 입력하여 주십시오' });
    }
  }
  //실제 서비스에서는 휴대폰 본인인증 등 무분별한 등록을 막을 logic이 필요함
})

router.post('/username', (req, res) => {
  const username = req.body.username;
  // Only check username, no need to check password as this is a mock
  if (!username) {
    res.status(400).send({ error: 'Bad request' });
    return;
  } else {
    res.cookie('username', username);
    // If sign-in succeeded, redirect to `/home`.
    res.json(username);
  }
});

/**
* 사용자 자격 증명을 확인하고 사용자가 로그인하도록합니다.
 * 사전 등록이 필요하지 않습니다.
 *`username`이 빈 문자열이 아닌지 확인하고 비밀번호를 무시합니다.
  * Verifies user credential and let the user sign-in.
 * No preceding registration required.
 * This only checks if `username` is not empty string and ignores the password.
 **/
router.post('/password', (req, res) => {
  if (!req.body.password) {
    res.status(401).json({ error: 'Enter at least one random letter.' });
    return;
  }
  const userkey = req.cookies.username + "::" + req.body.password;
  console.log("regi" + registerObjects[userkey]);
  console.log("sign" + signinObjects[userkey]);
  if (!registerObjects[userkey] && !signinObjects[userkey]) {
    res.status(401).json({ error: 'Id와 인증번호를 확인하여 주십시오. FiDo2 기반 DID 서비스를 사용하려는 웹에서 먼저 등록해야 합니다. 등록이 완료된 상태라면 인증과 등록 중 올바른 메뉴를 선택하세요.' });
    return;
  }
  res.cookie('username', userkey);
  res.cookie('signed-in', 'yes');
  res.json(userkey);
});

router.get('/signout', (req, res) => {
  // Remove cookies
  res.clearCookie('username');
  res.clearCookie('signed-in');
  // Redirect to `/`
  res.redirect(302, '/');
});

/**
* 자격 증명 ID를 반환
 * (이 서버는 사용자 이름 당 하나의 키만 저장합니다.)
 *  * Returns a credential id
 * (This server only stores one key per username.)
 * Response format:
 * ```{
 *   username: String,
 *   credentials: [Credential]
 * }```
 
 Credential
 ```
 {
   credId: String,
   publicKey: String,
   aaguid: ??,
   prevCounter: Int
 };
 ```
 **/

/****************************************************************************************수정필요 */
router.post('/getKeys', csrfCheck, sessionCheck, (req, res) => {
  const user = db.get('users')
    .find({ id: req.cookies.username })
    .value();

  console.log(user || {});
  res.json(user || {});
});

/**
* 사용자에게 첨부 된 자격 증명 ID를 제거합니다
 * 빈 JSON`{}`로 응답
 *  * Removes a credential id attached to the user
 * Responds with empty JSON `{}`
 **/
router.post('/removeKey', csrfCheck, sessionCheck, (req, res) => {
  const credId = req.query.credId;
  const username = req.cookies.username;
  const user = db.get('users')
    .find({ username: username })
    .value();

  const newCreds = user.credentials.filter(cred => {
    // Leave credential ids that do not match
    return cred.credId !== credId;
  });

  db.get('users')
    .find({ username: username })
    .assign({ credentials: newCreds })
    .write();

  res.json({});
});

router.get('/resetDB', (req, res) => {
  db.set('users', []).write();
  const users = db.get('users').value();
  res.json(users);
});

/****************************************************************************************수정필요 */

/**
* navigator.credential.create ()를 호출하는 데 필요한 정보로 응답
 * 입력은 출력과 비슷한 형식으로 'rebody.body'를 통해 전달됩니다.
 *  Respond with required information to call navigator.credential.create()
 * Input is passed via `req.body` with similar format as output
 * Output format:
 * ```{
     rp: {
       id: String,
       name: String
     },
     user: {
       displayName: String,
       id: String,
       name: String
     },
     publicKeyCredParams: [{  // @herrjemand
       type: 'public-key', alg: -7
     }],
     timeout: Number,
     challenge: String,
     excludeCredentials: [{
       id: String,
       type: 'public-key',
       transports: [('ble'|'nfc'|'usb'|'internal'), ...]
     }, ...],
     authenticatorSelection: {
       authenticatorAttachment: ('platform'|'cross-platform'),
       requireResidentKey: Boolean,
       userVerification: ('required'|'preferred'|'discouraged')
     },
     attestation: ('none'|'indirect'|'direct')
 * }
 **/
router.post('/registerRequest', csrfCheck, sessionCheck, async (req, res) => {
  console.log(req.cookies.username);
  const username = registerObjects[req.cookies.username].id;
  let user = db.get('users')
    .find({ id: username })
    .value();
  try {
    if (!user) {
      user = registerObjects[req.cookies.username];
      const response = await f2l.attestationOptions();
      response.user = {
        displayName: 'No name',
        id: user.id,
        name: user.username
      };
      response.challenge = coerceToBase64Url(response.challenge, 'challenge');
      res.cookie('challenge', response.challenge);
      response.pubKeyCredParams = [];
      // const params = [-7, -35, -36, -257, -258, -259, -37, -38, -39, -8];
      const params = [-7, -257];
      for (let param of params) {
        response.pubKeyCredParams.push({ type: 'public-key', alg: param });
      }
      const as = {}; // authenticatorSelection
      const aa = req.body.authenticatorSelection.authenticatorAttachment;
      const rr = req.body.authenticatorSelection.requireResidentKey;
      const uv = req.body.authenticatorSelection.userVerification;
      const cp = req.body.attestation; // attestationConveyancePreference
      let asFlag = false;

      if (aa && (aa == 'platform' || aa == 'cross-platform')) {
        asFlag = true;
        as.authenticatorAttachment = aa;
      }
      if (rr && typeof rr == 'boolean') {
        asFlag = true;
        as.requireResidentKey = rr;
      }
      if (uv && (uv == 'required' || uv == 'preferred' || uv == 'discouraged')) {
        asFlag = true;
        as.userVerification = uv;
      }
      if (asFlag) {
        response.authenticatorSelection = as;
      }
      if (cp && (cp == 'none' || cp == 'indirect' || cp == 'direct')) {
        response.attestation = cp;
      }
      res.json(response);
    } else {
      res.status(400).send({ error: "해당 계정에 대한 Fido2 Credential이 존재합니다." });
    }
  } catch (e) {
    console.log(e);
    res.status(400).send({ error: e });
  }
});
/**
 * Register user credential.
* 사용자 자격 증명을 등록하십시오.
 * Input format:
 * ```{
     id: String,
     type: 'public-key',
     rawId: String,
     response: {
       clientDataJSON: String,
       attestationObject: String,
       signature: String,
       userHandle: String
     }
 * }```
 **/

router.post('/registerResponse', csrfCheck, sessionCheck, async (req, res) => {
  const username = req.cookies.username;
  const challenge = coerceToArrayBuffer(req.cookies.challenge, 'challenge');

  try {
    const clientAttestationResponse = { response: {} };
    clientAttestationResponse.rawId =
      coerceToArrayBuffer(req.body.rawId, "rawId");
    clientAttestationResponse.response.clientDataJSON =
      coerceToArrayBuffer(req.body.response.clientDataJSON, "clientDataJSON");
    clientAttestationResponse.response.attestationObject =
      coerceToArrayBuffer(req.body.response.attestationObject, "attestationObject");

    let origin = '';
    if (req.get('User-Agent').indexOf('okhttp') > -1) {
      const octArray = process.env.ANDROID_SHA256HASH.split(':').map(h => parseInt(h, 16));
      const androidHash = coerceToBase64Url(octArray, 'Android Hash');
      origin = `android:apk-key-hash:${androidHash}`; // TODO: Generate
    } else {
      origin = `https://${req.get('host')}`;
    }

    const attestationExpectations = {
      challenge: challenge,
      origin: origin,
      factor: "either"
    };

    const regResult = await f2l.attestationResult(clientAttestationResponse, attestationExpectations);

    const credential = {
      credId: coerceToBase64Url(regResult.authnrData.get("credId"), 'credId'),
      publicKey: regResult.authnrData.get("credentialPublicKeyPem"),
      aaguid: coerceToBase64Url(regResult.authnrData.get("aaguid"), 'aaguid'),
      prevCounter: regResult.authnrData.get("counter")
    };

    let user = db.get('users')
      .find({ id: registerObjects[username].id })
      .value();
    if (!user) {
      user = {};

      user.id = registerObjects[username].id;
      user.url = registerObjects[username].url;
      user.name = registerObjects[username].username;
      user.credentials = credential;

      await db.get('users')
        .push(user)
        .write();

      res.clearCookie('challenge');
      res.clearCookie('username');
      delete registerObjects[req.cookies.username];

      await chain.insert(user.id, credential.publicKey);
      // Respond with user info
      user.message = "등록완료!!";
      res.json(user);
    } else {
      res.clearCookie('challenge');
      res.clearCookie('username');
      delete registerObjects[req.cookies.username];
      // Respond with user info
      res.status(400).send({ message: "해당 유저의 credentials이 존재합니다!" });
    }
  } catch (e) {
    res.clearCookie('challenge');
    res.clearCookie('username');
    delete registerObjects[req.cookies.username];
    res.status(400).send({ error: e.message });
  }
});

router.post('/confirmregister', (req, res) => {
  const memkey = req.body.username + '::' + req.body.registerNumber;
  const dbkey = new URL(req.headers.origin).hostname + '::' + req.body.username;
  console.log(memkey, dbkey);
  if (db.get('users').find({ id: dbkey }).value()) {
    res.json({ message: "등록이 성공적으로 완료되었습니다." });
  } else if (registerObjects[memkey]) {
    res.json({ message: "등록 중입니다. 잠시만 기다려 주십시오" });
  } else {
    res.json({ message: "등록에 실패하였습니다. 처음부터 다시 시도해주세요" });
  }
})
/**
 * Respond with required information to call navigator.credential.get()
 * Input is passed via `req.body` with similar format as output
* navigator.credential.get ()을 호출하기 위해 필요한 정보로 응답
 * 입력은 출력과 비슷한 형식으로 'rebody.body'를 통해 전달됩니다.
 * Output format:
 * ```{
     challenge: String,
     userVerification: ('required'|'preferred'|'discouraged'),
     allowCredentials: [{
       id: String,
       type: 'public-key',
       transports: [('ble'|'nfc'|'usb'|'internal'), ...]
     }, ...]
 * }```
 **/
router.post('/registersignin', (req, res) => {
  if (req.get('User-Agent').indexOf('okhttp') > -1) {
    res.status(400).send({ error: 'Bad request' });
    return;
  } else {
    const username = req.body.username;
    const urlimsi = new URL(req.headers.origin);
    const url = urlimsi.hostname;
    const registerNumber = req.body.registerNumber;
    const registerObjectId = username + '::' + registerNumber;
    console.log(signinObjects[registerObjectId]);
    if (!signinObjects[registerObjectId]) {
      signinObjects[registerObjectId] = {
        id: url + '::' + username,
        username: username,
        url: url
      }
      res.json({ message: '5분안에 MyDID 앱에서 등록절차를 마무리하신 후 확인 버튼을 눌러주세요.' });
      console.log(registerObjectId, url);
      setTimeout(() => {
        delete signinObjects[registerObjectId];
      }, 300000)
    }
    else {
      res.json({ message: '다른 인증 번호를 입력하여 주십시오' });
    }
  }
  //실제 서비스에서는 휴대폰 본인인증 등 무분별한 등록을 막을 logic이 필요함
})

router.post('/signinRequest', csrfCheck, async (req, res) => {
  try {
    console.log(req.cookies.username);
    if (signinObjects[req.cookies.username]) {

      const username = signinObjects[req.cookies.username];
      const user = db.get('users')
        .find({ id: username.id })
        .value();

      if (!user) {
        // Send empty response if user is not registered yet.
        res.json({ error: 'User not found.' });
        return;
      }

      const credId = user.credentials.credId;

      const response = await f2l.assertionOptions();

      // const response = {};
      response.userVerification = req.body.userVerification || 'required';
      response.challenge = coerceToBase64Url(response.challenge, 'challenge');
      res.cookie('challenge', response.challenge);

      response.allowCredentials = [];
      response.allowCredentials.push({
        id: credId,
        type: 'public-key',
        transports: ['internal']
      });
      res.json(response);
    } else {
      res.status(401).json({ error: 'Id와 인증번호를 확인하여 주십시오. FiDo2 기반 DID 서비스를 사용하려는 웹에서 먼저 인증요청을 해야 합니다.' });
    }
  } catch (e) {
    res.status(400).json({ error: e });
  }
});

/**
 * Authenticate the user.
* 사용자를 인증하십시오.
 * Input format:
 * ```{
     id: String,
     type: 'public-key',
     rawId: String,
     response: {
       clientDataJSON: String,
       authenticatorData: String,
       signature: String,
       userHandle: String
     }
 * }```
 **/
router.post('/signinResponse', csrfCheck, async (req, res) => {
  // Query the user
  const user = db.get('users')
    .find({ id: signinObjects[req.cookies.username].id })
    .value();

  let credential = null;
  if (user.credentials.credId === req.body.id) {
    credential = user.credentials;
  }
  try {
    if (!credential) {
      throw 'Authenticating credential not found.';
    }

    const challenge = coerceToArrayBuffer(req.cookies.challenge, 'challenge');
    const origin = `https://${req.get('host')}`; // TODO: Temporary work around for scheme

    const clientAssertionResponse = { response: {} };
    clientAssertionResponse.rawId =
      coerceToArrayBuffer(req.body.rawId, "rawId");
    clientAssertionResponse.response.clientDataJSON =
      coerceToArrayBuffer(req.body.response.clientDataJSON, "clientDataJSON");
    clientAssertionResponse.response.authenticatorData =
      coerceToArrayBuffer(req.body.response.authenticatorData, "authenticatorData");
    clientAssertionResponse.response.signature =
      coerceToArrayBuffer(req.body.response.signature, "signature");
    clientAssertionResponse.response.userHandle =
      coerceToArrayBuffer(req.body.response.userHandle, "userHandle");
    const assertionExpectations = {
      challenge: challenge,
      origin: origin,
      factor: "either",
      publicKey: credential.publicKey,
      prevCounter: credential.prevCounter,
      userHandle: coerceToArrayBuffer(user.id, 'userHandle')
    };

    signinObjects[req.cookies.username] = { confirm: 0 }
    const result = await f2l.assertionResult(clientAssertionResponse, assertionExpectations);

    credential.prevCounter = result.authnrData.get("counter");

    db.get('users')
      .find({ id: req.cookies.id })
      .assign(user)
      .write();

    signinObjects[req.cookies.username] = { confirm: 1 }
    res.clearCookie('id');
    res.clearCookie('challenge');
    res.clearCookie('username');
    res.json(user);
  } catch (e) {
    res.clearCookie('id');
    res.clearCookie('challenge');
    res.clearCookie('username');
    res.status(400).json({ error: e });
  }
});
router.post('/confirmsignin', (req, res) => {
  const memkey = req.body.username + '::' + req.body.registerNumber;
  const dbkey = new URL(req.headers.origin).hostname + '::' + req.body.username;
  if (signinObjects[memkey].confirm === 1) {
    delete signinObjects[memkey];
    res.json({ message: "인증이 완료되었습니다!", key: '1' });
  } else {
    delete signinObjects[memkey];
    res.json({ message: "인증에 실패하였습니다. 처음부터 다시 시도해주세요" });
  }
})

module.exports = router;
