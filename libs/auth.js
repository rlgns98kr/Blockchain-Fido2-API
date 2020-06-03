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
var uniqid = require("uniqid");
var request = require("request");

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

var phoneNumbers = {
  '01049067547': {
    confirm: 'false'
  }
}
var registerObjects = {

};


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

router.post('/username', (req, res) => {
  const username = req.body.username;
  // Only check username, no need to check password as this is a mock
  if (!username) {
    res.status(400).send({ error: 'Bad request' });
    return;
  } else {
    let user = db.get('users')
      .find({ id: username })
      .value();
    if (!user) {
      // If sign-in succeeded, redirect to `/home`.

      var reginumber = parseInt(Math.random() * 999999);
      reginumber = reginumber.toString();
      if (reginumber.length !== 6) {
        const l = reginumber.length;
        for (let i = 0; i < 6 - l; i++) {
          reginumber = '0' + reginumber;
        }
      }


      var apiKey = "NCSCWSQYYSU7EEAL";
      var apiSecret = "JQ1WITPEUZXL3TAJQKUXHTJ8BZDLOJUK";
      var timestamp = Math.floor(new Date().getTime() / 1000);
      var salt = uniqid();
      var signature = crypto
        .createHmac("md5", apiSecret)
        .update(timestamp + salt)
        .digest("hex");
      var to = username;
      var from = "01049067547";
      var params = {
        api_key: apiKey,
        salt: salt,
        signature: signature,
        timestamp: timestamp,
        to: to,
        from: from,
        text: "본인확인을 위해 인증번호[" + reginumber + "] 를 입력해주세요. 타인에게 절대 유출 금지",
      };

      request.post({ url: "http://api.coolsms.co.kr/sms/1.5/send", formData: params }, (
        err,
        ress,
        body
      ) => {
        let sw = 0;
        console.log("body:", body);
        if (!err && ress.statusCode == "200") {
          sw = 1;
          registerObjects[username + '::' + reginumber] = {};
          registerObjects[username + '::' + reginumber].phone = username;
          res.cookie('username', username);
          res.json({ message: "문자메세지를 확인 후 인증번호를 입력하시어 등록을 마무리 해주시기 바랍니다." });
        } else {
          console.log(err);
          sw = -1
          res.json({ message: "문자메세지 전송에 실패하였습니다. 올바른 Phone Number를 입력 해주세요." })
        }
      });

      //인증번호 보내고 저장
    } else if (phoneNumbers[username]) {
      res.cookie('username', username);
      res.cookie('signed-in', 'yes');
      res.json({ message: "인증 버튼을 눌러 인증을 마무리 해주시길 바랍니다." });
    } else {
      res.json({ message: "등록된 휴대폰번호입니다." });
    }

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
  const userkey = req.cookies.username + '::' + req.body.password;
  if (!registerObjects[userkey]) {
    res.status(401).json({ error: '올바른 핸드폰 번호를 사용하여 주십시오!' });
    return;
  }
  else {
    res.cookie('signed-in', 'yes');
    res.cookie('username', userkey);
    res.status(200).json({ message: '인증완료! 지문을 등록하여 주십시오!', key: 1 })
  }
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
  if (registerObjects[req.cookies.username]) {
    const username = registerObjects[req.cookies.username].phone;
    let user = db.get('users')
      .find({ id: username })
      .value();
    try {
      if (!user) {
        user = registerObjects[req.cookies.username];
        const response = await f2l.attestationOptions();
        response.user = {
          id: user.phone,
          displayName: 'No name',
          name: user.phone
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
  } else {
    res.status(400).json({ error: "세션이 만료되었습니다. '다시 입력하기'를 눌러 다시 시도해주세요!" })
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
      .find({ id: registerObjects[username].phone })
      .value();
    if (!user) {
      user = {};

      user.id = registerObjects[username].phone;
      user.credentials = credential;

      await db.get('users')
        .push(user)
        .write();


      delete registerObjects[req.cookies.username];

      await chain.insert(user.id, credential.publicKey);
      // Respond with user info
      user.message = "등록완료!!";
      res.clearCookie('challenge');
      res.clearCookie('username');
      res.clearCookie('signed-in');
      res.json(user);
    } else {

      delete registerObjects[req.cookies.username];
      // Respond with user info
      res.clearCookie('challenge');
      res.clearCookie('username');
      res.clearCookie('signed-in');
      res.status(400).send({ message: "해당 유저의 credentials이 존재합니다!" });
    }
  } catch (e) {

    delete registerObjects[req.cookies.username];
    res.clearCookie('challenge');
    res.clearCookie('username');
    res.status(400).send({ error: e.message });
  }
});
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
  const phoneNumber = req.body.phoneNumber;
  if (req.get('User-Agent').indexOf('okhttp') > -1) {
    res.status(400).send({ error: 'Bad request' });
    return;
  } else {
    const user = db.get('users')
      .find({ id: phoneNumber })
      .value();
    if (!user) {
      res.json({ message: '등록되지 않은 휴대폰 번호입니다!', key: '0' });
    }
    else {
      phoneNumbers[phoneNumber] = { confirm: false };
      const a = setInterval(() => {
        if (phoneNumbers[phoneNumber]) {
          if (phoneNumbers[phoneNumber].confirm === true) {
            delete phoneNumbers[phoneNumber];
            res.json({ message: '인증 성공!', key: '1' });
            clearInterval(a);
            clearTimeout(b);
          }
        } else {
          res.json({ message: '지문 인증 실패!', key: '3' });
          clearInterval(a);
          clearTimeout(b);
        }
      }, 100)
      const b = setTimeout(() => {
        clearInterval(a);
        delete phoneNumbers[phoneNumber];
        res.json({ message: '인증 시간 초과! 다시 인증요청을 해주세요', key: '2' })
      }, 180000);

    }
  }
  //실제 서비스에서는 휴대폰 본인인증 등 무분별한 등록을 막을 logic이 필요함
})

router.post('/signinRequest', csrfCheck, async (req, res) => {
  try {

    const username = req.cookies.username;
    const user = db.get('users')
      .find({ id: username })
      .value();

    if (!user) {
      // Send empty response if user is not registered yet.
      res.json({ error: 'User not found.' });
      return;
    }
    const pub = await chain.query(req.cookies.username);
    if (pub.toString() !== user.credentials.publicKey.toString()) {
      res.json({ error: 'This public is not valid' });
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
    .find({ id: req.cookies.username })
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

    const result = await f2l.assertionResult(clientAssertionResponse, assertionExpectations);

    credential.prevCounter = result.authnrData.get("counter");

    db.get('users')
      .find({ id: req.cookies.username })
      .assign(user)
      .write();

    phoneNumbers[req.cookies.username].confirm = true;

    res.clearCookie('challenge');
    res.clearCookie('username');
    res.json(user);
  } catch (e) {
    res.clearCookie('challenge');
    res.clearCookie('username');
    delete phoneNumbers[req.cookies.id];
    res.status(400).json({ error: e });
  }
});

module.exports = router;
